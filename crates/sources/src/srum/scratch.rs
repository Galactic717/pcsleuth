//! The scratch folder for a SRUM copy and for ESE's temporary files.
//!
//! The elevated snapshot puts a copy of `SRUDB.dat` here, a database only administrators may read.
//! A folder made the usual way in the temp directory inherits the user's access list, so any other
//! process of the same user could read the copy, swap a file before the elevated process replays
//! it, or plant a link where an elevated tool is about to write. So the folder is:
//!
//! - **new**: made by `CreateDirectoryW`, which fails if the name exists, under a name with 128
//!   random bits (`pcsleuth-<tag>-<32 hex digits>`) that cannot be guessed before it exists;
//! - **private**: its access list is protected (not inherited) and names SYSTEM and Administrators
//!   only, with inheritance for what is created inside, `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`;
//! - **held**: this process keeps a handle open that does not share delete, so the folder cannot be
//!   renamed away and replaced by another one of the same name while it is in use.
//!
//! A process that is not elevated (the tests, and `read_usage` on a copy the caller already owns)
//! must be able to use its own folder, so there the current user is added to the list. That folder
//! holds only ESE's temporary files for a copy the user could already read. Elevated, the user is
//! left out on purpose: that is the case the protection is for.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
    CreateWellKnownSid, GetLengthSid, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

/// `SECURITY_DESCRIPTOR_REVISION`.
const DESCRIPTOR_REVISION: u32 = 1;
/// `SECURITY_MAX_SID_SIZE`.
const MAX_SID_BYTES: usize = 68;

/// A folder under the system temp dir that is deleted, with everything in it, on drop. See the
/// module notes for how it is made.
pub(super) struct ScratchDir {
    path: PathBuf,
    /// Open without delete sharing, so the folder cannot be renamed or removed by anyone else.
    guard: Option<File>,
}

impl ScratchDir {
    pub(super) fn new(tag: &str) -> io::Result<ScratchDir> {
        let sids = allowed_sids(super::copy::is_elevated())?;
        let path = std::env::temp_dir().join(folder_name(tag, random_128()?));
        create_private_dir(&path, &sids)?;
        let guard = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(&path);
        match guard {
            Ok(guard) => Ok(ScratchDir {
                path,
                guard: Some(guard),
            }),
            Err(err) => {
                let _ = std::fs::remove_dir(&path);
                Err(err)
            }
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Delete the folder now and report whether that worked. Dropping does the same but has
    /// nowhere to report a failure.
    pub(super) fn remove(mut self) -> io::Result<()> {
        self.release()
    }

    fn release(&mut self) -> io::Result<()> {
        drop(self.guard.take());
        let path = std::mem::take(&mut self.path);
        if path.as_os_str().is_empty() {
            return Ok(());
        }
        match std::fs::remove_dir_all(&path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

/// `pcsleuth-<tag>-` and the 128 random bits as 32 lower case hex digits.
fn folder_name(tag: &str, random: [u8; 16]) -> String {
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("pcsleuth-{tag}-{hex}")
}

/// 128 random bits from the system generator, the one `power::create_output_dir` uses.
fn random_128() -> io::Result<[u8; 16]> {
    // The same system generator Rust's own standard library uses; it cannot fail on Windows 10+.
    windows::core::link!("bcryptprimitives.dll" "system" fn ProcessPrng(data: *mut u8, len: usize) -> i32);

    let mut random = [0u8; 16];
    // SAFETY: the pointer and length describe `random` exactly.
    if unsafe { ProcessPrng(random.as_mut_ptr(), random.len()) } == 0 {
        return Err(io::Error::other("the system random generator failed"));
    }
    Ok(random)
}

/// A Win32 failure as an I/O error that keeps its kind (denied, not found, already exists).
fn io_error(error: windows::core::Error) -> io::Error {
    let hresult = error.code().0 as u32;
    if hresult >> 16 == 0x8007 {
        io::Error::from_raw_os_error((hresult & 0xFFFF) as i32)
    } else {
        io::Error::other(error)
    }
}

/// The SIDs the folder admits: SYSTEM and Administrators, and the current user unless the process
/// is elevated (see the module notes).
fn allowed_sids(elevated: bool) -> io::Result<Vec<Vec<u8>>> {
    let mut sids = vec![
        well_known_sid(WinLocalSystemSid)?,
        well_known_sid(WinBuiltinAdministratorsSid)?,
    ];
    if !elevated {
        sids.push(current_user_sid()?);
    }
    Ok(sids)
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Vec<u8>> {
    let mut sid = vec![0u8; MAX_SID_BYTES];
    let mut size = MAX_SID_BYTES as u32;
    // SAFETY: `sid` is writable for `size` bytes and `size` is a valid in/out pointer.
    unsafe { CreateWellKnownSid(kind, None, Some(PSID(sid.as_mut_ptr().cast())), &mut size) }
        .map_err(io_error)?;
    sid.truncate(size as usize);
    Ok(sid)
}

fn current_user_sid() -> io::Result<Vec<u8>> {
    let mut token = HANDLE::default();
    // SAFETY: `token` outlives the call; the pseudo handle of the current process needs no close.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(io_error)?;
    let sid = token_user_sid(token);
    // SAFETY: `token` was opened above and is closed once.
    let _ = unsafe { CloseHandle(token) };
    sid
}

fn token_user_sid(token: HANDLE) -> io::Result<Vec<u8>> {
    let mut needed = 0u32;
    // SAFETY: a null buffer of size 0 only asks for the size needed; `needed` is a valid pointer.
    // The call fails with "insufficient buffer" by design, so its result is not the answer.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::other("the token has no user"));
    }
    // 8-byte units give the alignment TOKEN_USER needs.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: the buffer is writable for `needed` bytes and `needed` is a valid in/out pointer.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(io_error)?;
    // SAFETY: the call above wrote a TOKEN_USER at the start of the buffer, and the SID it points
    // at lies inside the same buffer, which outlives this copy.
    let sid = unsafe {
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let len = GetLengthSid(user.User.Sid) as usize;
        std::slice::from_raw_parts(user.User.Sid.0.cast::<u8>(), len).to_vec()
    };
    Ok(sid)
}

/// Create `path` as a new directory whose access list is protected and grants `FILE_ALL_ACCESS`,
/// inherited by what is created inside, to exactly `sids`. Fails if `path` exists.
fn create_private_dir(path: &Path, sids: &[Vec<u8>]) -> io::Result<()> {
    let ace_bytes = |sid: &Vec<u8>| size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid.len();
    let acl_bytes =
        (size_of::<ACL>() + sids.iter().map(ace_bytes).sum::<usize>()).next_multiple_of(4);
    // 4-byte units give the alignment an ACL needs.
    let mut acl = vec![0u32; acl_bytes / 4];
    let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
    // SAFETY: `acl` is writable for `acl_bytes` bytes, and every SID is a complete SID.
    unsafe {
        InitializeAcl(acl_ptr, acl_bytes as u32, ACL_REVISION).map_err(io_error)?;
        for sid in sids {
            AddAccessAllowedAceEx(
                acl_ptr,
                ACL_REVISION,
                CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                FILE_ALL_ACCESS.0,
                PSID(sid.as_ptr().cast_mut().cast()),
            )
            .map_err(io_error)?;
        }
    }
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_ptr = PSECURITY_DESCRIPTOR(std::ptr::from_mut(&mut descriptor).cast::<c_void>());
    // SAFETY: `descriptor` and `acl` outlive every call below, including `CreateDirectoryW`.
    unsafe {
        InitializeSecurityDescriptor(descriptor_ptr, DESCRIPTOR_REVISION).map_err(io_error)?;
        SetSecurityDescriptorDacl(descriptor_ptr, true, Some(acl_ptr.cast_const()), false)
            .map_err(io_error)?;
        // Without this, access entries of the parent folder would be added to the list.
        SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
            .map_err(io_error)?;
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor_ptr.0,
        bInheritHandle: false.into(),
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL terminated and `attributes` points at the descriptor above.
    unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&attributes)) }.map_err(io_error)
}

#[cfg(test)]
mod tests {
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetAce, GetFileSecurityW, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl,
    };

    use super::*;

    /// The protected flag and the access entries of `path`: (flags, mask, SID bytes) each.
    fn read_dacl(path: &Path) -> (bool, Vec<(u8, u32, Vec<u8>)>) {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut needed = 0u32;
        // SAFETY: a null buffer of size 0 only asks for the size; the failure is by design.
        let _ = unsafe {
            GetFileSecurityW(
                PCWSTR(wide.as_ptr()),
                DACL_SECURITY_INFORMATION.0,
                None,
                0,
                &mut needed,
            )
        };
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let descriptor = PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast());
        // SAFETY: the buffer is writable for `needed` bytes.
        assert!(
            unsafe {
                GetFileSecurityW(
                    PCWSTR(wide.as_ptr()),
                    DACL_SECURITY_INFORMATION.0,
                    Some(descriptor),
                    needed,
                    &mut needed,
                )
            }
            .as_bool()
        );
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: `descriptor` is the self-relative descriptor just read.
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.unwrap();
        let (mut present, mut defaulted) = (false.into(), false.into());
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: as above; the out pointers are valid.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            .unwrap();
        assert!(present.as_bool() && !acl.is_null());
        // SAFETY: `acl` points into `buffer`, which is alive.
        let count = unsafe { (*acl).AceCount };
        let mut entries = Vec::new();
        for index in 0..u32::from(count) {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: `index` is below the ACE count of `acl`.
            unsafe { GetAce(acl, index, &mut ace) }.unwrap();
            // SAFETY: an access allowed ACE: header, mask, then the SID, all inside `buffer`.
            let entry = unsafe {
                let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                assert_eq!(ace.Header.AceType, 0, "only ACCESS_ALLOWED ACEs");
                let sid = PSID(std::ptr::from_ref(&ace.SidStart).cast_mut().cast());
                let len = GetLengthSid(sid) as usize;
                (
                    ace.Header.AceFlags,
                    ace.Mask,
                    std::slice::from_raw_parts(sid.0.cast::<u8>(), len).to_vec(),
                )
            };
            entries.push(entry);
        }
        (control & SE_DACL_PROTECTED.0 != 0, entries)
    }

    #[test]
    fn the_folder_list_is_protected_and_names_only_system_administrators_and_the_caller() {
        let dir = ScratchDir::new("test").unwrap();
        let (protected, entries) = read_dacl(dir.path());
        assert!(protected, "inherited entries would be added otherwise");
        let expected = allowed_sids(super::super::copy::is_elevated()).unwrap();
        let sids: Vec<_> = entries.iter().map(|(_, _, sid)| sid.clone()).collect();
        assert_eq!(
            sids, expected,
            "no entry beyond SYSTEM, Administrators and, unelevated, the user"
        );
        for (flags, mask, _) in &entries {
            assert_eq!(
                u32::from(*flags),
                (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE).0
            );
            assert_eq!(*mask, FILE_ALL_ACCESS.0);
        }
        // The first two are the well known SIDs, whoever runs this.
        assert_eq!(sids[0], well_known_sid(WinLocalSystemSid).unwrap());
        assert_eq!(
            sids[1],
            well_known_sid(WinBuiltinAdministratorsSid).unwrap()
        );
        // What is created inside inherits the same list.
        let file = dir.path().join("inner.txt");
        std::fs::write(&file, b"x").unwrap();
        let (_, inherited) = read_dacl(&file);
        let inherited_sids: Vec<_> = inherited.into_iter().map(|(_, _, sid)| sid).collect();
        assert_eq!(inherited_sids, sids);
    }

    #[test]
    fn a_name_that_exists_is_never_reused() {
        let dir = ScratchDir::new("test").unwrap();
        let sids = allowed_sids(false).unwrap();
        let err = create_private_dir(dir.path(), &sids).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn names_carry_128_random_bits_and_are_unique() {
        let name = folder_name("tag", [0xAB; 16]);
        assert_eq!(name, format!("pcsleuth-tag-{}", "ab".repeat(16)));
        let first = ScratchDir::new("test").unwrap();
        let second = ScratchDir::new("test").unwrap();
        assert_ne!(first.path(), second.path());
        let leaf = first.path().file_name().unwrap().to_str().unwrap();
        let hex = leaf.strip_prefix("pcsleuth-test-").unwrap();
        assert!(hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_ne!(random_128().unwrap(), random_128().unwrap());
    }

    #[test]
    fn the_folder_cannot_be_renamed_while_in_use_and_is_deleted_on_drop_or_remove() {
        let dropped = ScratchDir::new("test").unwrap();
        let moved = dropped.path().with_extension("moved");
        assert!(
            std::fs::rename(dropped.path(), &moved).is_err(),
            "another process could swap the folder if this worked"
        );
        std::fs::write(dropped.path().join("file"), b"x").unwrap();
        let path = dropped.path().to_path_buf();
        drop(dropped);
        assert!(!path.exists());

        let removed = ScratchDir::new("test").unwrap();
        let path = removed.path().to_path_buf();
        std::fs::write(path.join("file"), b"x").unwrap();
        removed.remove().unwrap();
        assert!(!path.exists());
    }
}
