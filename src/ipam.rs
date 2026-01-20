pub struct IpAllocator {
    pub used: Vec<bool>, // size is 0-255
}

impl IpAllocator {
    pub fn new() -> Self {
        let mut used = vec![false; 256];
        used[0] = true; // Network ID
        used[1] = true; // Gateway
        used[255] = true; // BroadCast

        Self { used }
    }

    pub fn allocate(&mut self) -> Option<u8> {
        for (i, used) in self.used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Some(i as u8);
            }
        }
        None
    }

    pub fn free(&mut self, octet: u8) {
        if octet > 0 && octet < 255 {
            self.used[octet as usize] = false;
        }
    }

    /// Try to allocate a specific IP octet. Returns true if successful, false if already in use.
    pub fn try_allocate_specific(&mut self, octet: u8) -> bool {
        if octet > 1 && octet < 255 && !self.used[octet as usize] {
            self.used[octet as usize] = true;
            true
        } else {
            false
        }
    }
}
