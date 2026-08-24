# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""STM32F0 reset/clock control and the flash interface.

WHY THESE CANNOT BE LEFT TO THE CATCH-ALL.  ChibiOS' ``stm32_clock_init()``
(``os/hal/ports/STM32/STM32F0xx/hal_lld.c``) is a chain of
*write-then-read-back-until-equal* loops, and the busy-wait breaker is exactly
wrong for those (playbook 2.40 / 2.100): the breaker escalates the value it
returns, so a compare against a *specific* value can never succeed.  Measured on the
bare-march boot of a sibling STM32F072 image: **1,425,632 escalating reads** of
``RCC->CFGR`` at one PC, with no fault and no other symptom.

The two shapes in that function:

* ``RCC->CR |= HSION; while (!(RCC->CR & HSIRDY));`` -- an enable/ready pair.
  Modelled by **mirroring each RDY bit from its own ON bit** (playbook 2.72),
  which is also what the silicon does and makes the *opposite* wait ("spin until
  it clears", which the USB/PLL reconfiguration paths use) work for free.
* ``RCC->CFGR |= SW; while ((RCC->CFGR & SWS) != (SW << 2));`` -- the system
  clock switch.  ``SWS[3:2]`` mirrors ``SW[1:0]``.

Everything else on the page is plain storage: the peripheral enable registers
(``AHBENR``/``APB1ENR``/``APB2ENR``) are read-modify-written constantly by
``rccEnableXXX`` and only ever have to read back what was written.

RESET VALUES MATTER (playbook 2.84).  ``RCC->CR`` powers up as ``0x00000083``
(HSION + HSIRDY + the default HSITRIM), and firmware that reads a clock register
*before* writing it will act on whatever we say.  ``stm32_clock_init``'s very
first statement is a read-modify-write of ``CR``.

THE FLASH INTERFACE is on its own page and matters for two reasons: ``ACR`` is
written with a latency value and re-read by other code, and ``SR`` must **not**
echo writes -- a status register that stores the clear-mask makes the
"wait until not busy" loop immortal (playbook 2.67).
"""
from __future__ import annotations

from typing import Any, Dict

from halucinator import hal_log
from halucinator.peripheral_models.generic import GenericPeripheral

from . import backend_ref

log = hal_log.getHalLogger()

#: STM32F072 flash page size (RM0091 3.3.1).  The wear-levelling EEPROM
#: backend erases one page at a time.
FLASH_PAGE_SIZE = 0x800
#: Everything above the 46,880-byte image is erased flash, and that is where
#: QMK's wear-levelling EEPROM emulation (``EEPROM_DRIVER = wear_leveling`` /
#: ``embedded_flash``) keeps its backing store.  Named only so the log can say
#: when an erase lands in it.
CONFIG_STORE_BASE = 0x0800C000
CONFIG_STORE_END = 0x08020000

# ---- RCC register offsets (RM0091 6.4) ------------------------------------
CR, CFGR, CIR = 0x00, 0x04, 0x08
APB2RSTR, APB1RSTR, AHBENR, APB2ENR, APB1ENR = 0x0C, 0x10, 0x14, 0x18, 0x1C
BDCR, CSR, AHBRSTR, CFGR2, CFGR3, CR2 = 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34

# CR
CR_HSION, CR_HSIRDY = 1 << 0, 1 << 1
CR_HSEON, CR_HSERDY = 1 << 16, 1 << 17
CR_PLLON, CR_PLLRDY = 1 << 24, 1 << 25
# CR2
CR2_HSI14ON, CR2_HSI14RDY = 1 << 0, 1 << 1
CR2_HSI48ON, CR2_HSI48RDY = 1 << 16, 1 << 17
# CSR / BDCR
CSR_LSION, CSR_LSIRDY = 1 << 0, 1 << 1
BDCR_LSEON, BDCR_LSERDY = 1 << 0, 1 << 1
# CFGR
CFGR_SW = 0x3
CFGR_SWS = 0x3 << 2


class Stm32F0Rcc(GenericPeripheral):
    """The RCC page (0x40021000).  ON/RDY pairs mirrored; SWS mirrors SW."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        # Reset values from RM0091 6.4.  HSI is on and stable out of reset.
        self.regs: Dict[int, int] = {
            CR: 0x00000083,
            CFGR: 0x00000000,
            CR2: 0x00000080,        # HSI14 calibration; HSI14ON off
            CSR: 0x00000000,
            BDCR: 0x00000000,
        }
        self._logged_sw = None
        log.info("Stm32F0Rcc: modelling RCC at 0x%08x (ON/RDY mirrored, "
                 "SWS mirrors SW)", address)

    # -- derived bits -------------------------------------------------------
    @staticmethod
    def _mirror(value: int, on: int, rdy: int) -> int:
        return (value | rdy) if value & on else (value & ~rdy)

    def _cr(self) -> int:
        v = self.regs.get(CR, 0)
        v = self._mirror(v, CR_HSION, CR_HSIRDY)
        v = self._mirror(v, CR_HSEON, CR_HSERDY)
        v = self._mirror(v, CR_PLLON, CR_PLLRDY)
        return v & 0xFFFFFFFF

    def _cr2(self) -> int:
        v = self.regs.get(CR2, 0)
        v = self._mirror(v, CR2_HSI14ON, CR2_HSI14RDY)
        v = self._mirror(v, CR2_HSI48ON, CR2_HSI48RDY)
        return v & 0xFFFFFFFF

    def _cfgr(self) -> int:
        v = self.regs.get(CFGR, 0)
        # SWS[3:2] follows SW[1:0]: the switch completes immediately, which is
        # the only honest answer when there is no real oscillator to wait for.
        return ((v & ~CFGR_SWS) | ((v & CFGR_SW) << 2)) & 0xFFFFFFFF

    # -- MMIO ---------------------------------------------------------------
    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        off = offset & ~0x3
        if off == CR:
            return self._cr()
        if off == CR2:
            return self._cr2()
        if off == CFGR:
            return self._cfgr()
        if off == CSR:
            return self._mirror(self.regs.get(CSR, 0), CSR_LSION, CSR_LSIRDY)
        if off == BDCR:
            return self._mirror(self.regs.get(BDCR, 0), BDCR_LSEON,
                                BDCR_LSERDY)
        return self.regs.get(off, 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        off = offset & ~0x3
        self.regs[off] = value & 0xFFFFFFFF
        if off == CFGR:
            sw = value & CFGR_SW
            if sw != self._logged_sw:
                self._logged_sw = sw
                log.info("Stm32F0Rcc: system clock source SW=%d (0=HSI, "
                         "1=HSE, 2=PLL) -- SWS will read back %d", sw, sw)
        return True


class Stm32F0FlashIface(GenericPeripheral):
    """The embedded-flash controller page (0x40022000).

    ``ACR`` is plain storage so the latency read-back succeeds.  ``SR`` is the
    important one: it must report **not busy, no error**, and must never echo a
    write -- ``FLASH_SR`` storing the firmware's clear-mask is what makes a
    wait-until-idle loop immortal (playbook 2.67).  ``CR``'s ``LOCK`` bit is
    modelled so the unlock sequence has an effect, because QMK's wear-levelling
    EEPROM writes the on-chip backing store and the flash region is mapped
    ``rwx``: the guest's own halfword ``strh`` instructions do the programming,
    so all this page has to do is not block them.
    """

    ACR, KEYR, OPTKEYR, SR, CR, AR, OBR, WRPR = (0x00, 0x04, 0x08, 0x0C,
                                                 0x10, 0x14, 0x1C, 0x20)
    SR_BSY, SR_PGERR, SR_WRPRTERR, SR_EOP = 1 << 0, 1 << 2, 1 << 4, 1 << 5
    CR_PG, CR_PER, CR_STRT, CR_LOCK = 1 << 0, 1 << 1, 1 << 6, 1 << 7
    KEY1, KEY2 = 0x45670123, 0xCDEF89AB

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.regs: Dict[int, int] = {self.ACR: 0x00000030,
                                     self.CR: self.CR_LOCK,
                                     self.OBR: 0x03FFFFFC,
                                     self.WRPR: 0xFFFFFFFF}
        self._key_state = 0
        self._ops = 0
        self.erases = 0
        self.erased_pages: list = []
        log.info("Stm32F0FlashIface: modelling the flash controller at "
                 "0x%08x (page erase BLANKS real guest flash)", address)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        off = offset & ~0x3
        if off == self.SR:
            # Never busy; report EOP so a completion poll ends. Errors clear.
            return self.SR_EOP
        return self.regs.get(off, 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        off = offset & ~0x3
        if off == self.KEYR:
            if self._key_state == 0 and value == self.KEY1:
                self._key_state = 1
            elif self._key_state == 1 and value == self.KEY2:
                self._key_state = 0
                self.regs[self.CR] = self.regs.get(self.CR, 0) & ~self.CR_LOCK
                log.info("Stm32F0FlashIface: firmware unlocked the flash "
                         "controller (it is about to program the config store)")
            else:
                self._key_state = 0
            return True
        if off == self.SR:
            return True                      # write-1-to-clear; nothing to keep
        if off == self.CR:
            self._ops += 1
            self.regs[off] = value & 0xFFFFFFFF
            if (value & self.CR_PER) and (value & self.CR_STRT):
                self._erase_page(self.regs.get(self.AR, 0))
                # STRT is cleared BY HARDWARE when the operation completes.
                # The driver does not clear it itself, so a model that
                # keeps it set fires a second, spurious erase on the *next*
                # `CR |= PER` -- at the PREVIOUS page address, because AR has
                # not been rewritten yet.  That doubles the erase count and
                # blanks a page the firmware did not name.
                self.regs[self.CR] = value & ~self.CR_STRT
            return True
        self.regs[off] = value & 0xFFFFFFFF
        return True

    # -- the erase actually erases -----------------------------------------
    def _erase_page(self, address: int) -> None:
        """Blank one 2 KB page of REAL guest flash.

        A controller that clears BSY, sets EOP and leaves the bytes alone is
        the tempting shortcut, and it is wrong twice over: a storage layer that
        reads the sector back would reject it (playbook 2.135), and -- the
        reason it matters here -- an attack whose only evidence is a log
        message proves the firmware *said* it wiped a page, not that anything
        was wiped.  The page address comes from the firmware's
        own ``FLASH->AR`` write, so the addresses in this log line are the
        firmware's, not ours.
        """
        page = address & ~(FLASH_PAGE_SIZE - 1)
        backend = backend_ref.get_backend()
        before = None
        if backend is not None:
            try:
                before = backend.read_memory(page, 4, 1)
                backend.write_memory(page, 1, b"\xff" * FLASH_PAGE_SIZE,
                                     raw=True)
            except Exception as exc:  # noqa: BLE001
                log.warning("Stm32F0FlashIface: page erase at 0x%08x failed "
                            "(%s)", page, exc)
                return
        self.erases += 1
        self.erased_pages.append(page)
        in_store = CONFIG_STORE_BASE <= page < CONFIG_STORE_END
        log.info("Stm32F0FlashIface: PAGE ERASE 0x%08x (%d bytes)%s -- first "
                 "word was 0x%08x, now 0xffffffff [erase #%d]", page,
                 FLASH_PAGE_SIZE,
                 " *** IN THE CONFIG/CALIBRATION STORE ***" if in_store else "",
                 before if before is not None else 0, self.erases)
