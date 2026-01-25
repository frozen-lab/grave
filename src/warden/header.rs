/// Header containing metadata for [`Page`]
///
/// ## Repr
///
/// All 6 bytes are used as,
///
/// - flag (0th bit of 0th byte)
/// - next_page_idx (1..7 of 0th, 1st, 2nd, 0..3 of 3rd bytes)
/// - total_free (4..7 of 3rd, 4th bytes)
/// - current_pointer (5th byte)
#[repr(transparent)]
struct PageHeader([u8; 6]);

impl PageHeader {
    #[inline]
    pub(super) const fn current_pointer(&self) -> u8 {
        self.0[5]
    }

    #[inline]
    pub(super) const fn set_current_pointer(&mut self, new_ptr: u8) {
        self.0[5] = new_ptr;
    }

    #[inline]
    pub(super) const fn total_free(&self) -> u16 {
        ((self.0[3] as u16 & 0x0F) << 8) | (self.0[4] as u16)
    }

    #[inline]
    pub(super) const fn next_index(&self) -> u32 {
        ((self.0[0] as u32 & 0x7F) << 0x14)
            | ((self.0[1] as u32) << 12)
            | ((self.0[2] as u32) << 4)
            | ((self.0[3] as u32 >> 4) & 15)
    }

    #[inline]
    pub(super) const fn is_bitmap(&self) -> bool {
        let id = self.0[0] >> 7;
        PageType::is_bitmap(id)
    }

    #[inline]
    pub(super) const fn is_adjarr(&self) -> bool {
        let id = self.0[0] >> 7;
        PageType::is_adjarr(id)
    }
}

#[repr(u8)]
#[derive(Debug)]
pub(super) enum PageType {
    BitMap,
    AdjArr,
}

impl PageType {
    #[inline]
    const fn is_bitmap(id: u8) -> bool {
        id == PageType::BitMap as u8
    }

    #[inline]
    const fn is_adjarr(id: u8) -> bool {
        id == PageType::AdjArr as u8
    }
}
