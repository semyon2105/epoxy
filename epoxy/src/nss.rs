use std::{
    ffi::{CStr, CString},
    marker::PhantomData,
    os::raw::{c_char, c_void},
    ptr::{self, null, null_mut},
    slice,
};

use thiserror::Error;
use tracing::{debug, error};
use xmlsec_nss_sys::*;

pub trait PinPrompt {
    fn prompt_pin(&self, pin_info: &PinInfo, token_name: String) -> Option<String>;
}

#[derive(Debug, Clone)]
pub struct PinInfo {
    pub cert: Option<String>,
    pub reason: String,
}

pub struct PinContext<'a> {
    pin_prompt: &'a dyn PinPrompt,
    pin_info: PinInfo,
}

impl<'a> PinContext<'a> {
    pub fn new(pin_prompt: &'a dyn PinPrompt, pin_info: PinInfo) -> PinContext<'a> {
        PinContext {
            pin_prompt,
            pin_info,
        }
    }
}

pub struct Nss {
    ptr: *mut NSSInitContext,
}

impl Drop for Nss {
    fn drop(&mut self) {
        unsafe { NSS_ShutdownContext(self.ptr) };
    }
}

impl Nss {
    pub fn initialize(nssdb_path: String) -> Result<Nss, InitError> {
        unsafe { PK11_SetPasswordFunc(Some(Self::password_func)) };

        let nssdb_path = CString::new(nssdb_path).map_err(|_| InitError::Ffi)?;
        let flags = 0;
        let ptr = unsafe {
            NSS_InitContext(
                nssdb_path.as_ptr(),
                null(),
                null(),
                null(),
                null_mut(),
                flags,
            )
        };

        Ok(Nss { ptr })
    }

    extern "C" fn password_func(
        token_ptr: *mut PK11SlotInfo,
        retry: PRBool,
        pin_context_ptr: *mut c_void,
    ) -> *mut c_char {
        if pin_context_ptr.is_null() {
            error!("bug: pin context not provided");
            return null_mut();
        }
        let PinContext {
            pin_prompt,
            pin_info,
        } = unsafe { &*(pin_context_ptr as *const PinContext) };

        if retry != 0 {
            return null_mut();
        }

        let token_name = Token::from_raw(token_ptr, false).name();

        debug!("requesting PIN for {}", token_name);
        let Some(pin) = pin_prompt.prompt_pin(pin_info, token_name) else {
            return null_mut();
        };

        let pin = CString::new(pin).unwrap_or_default();
        let pin_buf = pin.as_bytes_with_nul();
        let in_buf_ptr = pin_buf.as_ptr().cast::<c_char>();
        let out_buf_ptr = unsafe { PORT_Alloc(pin_buf.len()) } as *mut c_char;
        unsafe { ptr::copy_nonoverlapping(in_buf_ptr, out_buf_ptr, pin_buf.len()) };

        out_buf_ptr
    }

    pub fn get_tokens<'a>(&'a self) -> Option<TokenList<'a>> {
        let ty = CKM_SHA256_RSA_PKCS as u64;
        let need_rw = PR_FALSE as i32;
        let load_certs = PR_FALSE as i32;
        let pin_context_ptr = null_mut(); // not sure if this operation ever needs login in practice

        let ptr = unsafe { PK11_GetAllTokens(ty, need_rw, load_certs, pin_context_ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(TokenList::from_raw(ptr))
        }
    }

    pub fn get_token<'a>(&'a self, token_uri: &TokenUri) -> Option<Token<'a>> {
        let ptr = unsafe { PK11_FindSlotByName(token_uri.0.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(Token::from_raw(ptr, true))
        }
    }

    pub fn get_certs_in_token<'a>(
        &'a self,
        pin_context: &'a PinContext,
        token: &'a Token<'a>,
    ) -> Result<Option<CertList<'a>>, TokenAuthError> {
        let _logout_guard = self.authenticate_unfriendly(pin_context, token)?;

        let ptr = unsafe { PK11_ListCertsInSlot(token.ptr) };
        if ptr.is_null() {
            Ok(None)
        } else {
            Ok(Some(CertList::from_raw(ptr)))
        }
    }

    pub fn authenticate<'a>(
        &'a self,
        pin_context: &'a PinContext,
        token: &'a Token<'a>,
    ) -> Result<TokenLogoutGuard<'a>, TokenAuthError> {
        let pin_context_ptr = &raw const *pin_context as *mut c_void;
        let code = unsafe { PK11_Authenticate(token.ptr, PR_FALSE as i32, pin_context_ptr) };
        if code != _SECStatus_SECSuccess {
            return Err(TokenAuthError(()));
        }
        Ok(TokenLogoutGuard::new(token))
    }

    fn authenticate_unfriendly<'a>(
        &'a self,
        pin_context: &'a PinContext,
        token: &'a Token<'a>,
    ) -> Result<TokenLogoutGuard<'a>, TokenAuthError> {
        let pin_context_ptr = &raw const *pin_context as *mut c_void;
        if !token.is_friendly() {
            let code = unsafe { PK11_Authenticate(token.ptr, PR_FALSE as i32, pin_context_ptr) };
            if code != _SECStatus_SECSuccess {
                return Err(TokenAuthError(()));
            }
        }
        Ok(TokenLogoutGuard::new(token))
    }
}

#[derive(Debug, Error)]
pub enum InitError {
    #[error("C interop error")]
    Ffi,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenUri(CString);

pub struct TokenLogoutGuard<'a> {
    token: &'a Token<'a>,
}

impl<'a> TokenLogoutGuard<'a> {
    fn new(token: &'a Token<'a>) -> TokenLogoutGuard<'a> {
        TokenLogoutGuard { token }
    }
}

impl<'a> Drop for TokenLogoutGuard<'a> {
    fn drop(&mut self) {
        unsafe {
            PK11_Logout(self.token.ptr);
        }
    }
}

#[derive(Debug, Error)]
#[error("token auth failed")]
pub struct TokenAuthError(());

#[derive(Debug)]
pub struct SecItem(SECItem);

impl Drop for SecItem {
    fn drop(&mut self) {
        unsafe { SECITEM_FreeItem(&mut self.0, PR_FALSE as i32) };
    }
}

impl Clone for SecItem {
    fn clone(&self) -> Self {
        Self::new(&self.0)
    }
}

impl AsRef<[u8]> for SecItem {
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.0.data, self.0.len as usize) }
    }
}

impl SecItem {
    fn new(value: &SECItem) -> SecItem {
        let mut cloned = SECItem {
            type_: SECItemType_siBuffer,
            data: null_mut(),
            len: 0,
        };
        unsafe { SECITEM_CopyItem(null_mut(), &mut cloned, value) };
        SecItem(cloned)
    }

    pub fn as_ptr(&self) -> *const SECItem {
        &self.0
    }
}

pub struct Token<'a> {
    ptr: *mut PK11SlotInfo,
    is_owned: bool,
    _marker: PhantomData<&'a Nss>,
}

impl<'a> Drop for Token<'a> {
    fn drop(&mut self) {
        if self.is_owned {
            unsafe { PK11_FreeSlot(self.ptr) }
        }
    }
}

impl<'a> Token<'a> {
    fn from_raw(ptr: *mut PK11SlotInfo, is_owned: bool) -> Token<'a> {
        Token {
            ptr,
            is_owned,
            _marker: PhantomData,
        }
    }

    pub fn uri(&self) -> TokenUri {
        let uri_ptr = unsafe { PK11_GetTokenURI(self.ptr as *mut _) };
        let uri = unsafe { CStr::from_ptr(uri_ptr).to_owned() };
        unsafe { PORT_Free(uri_ptr as *mut c_void) }; // `PK11_GetTokenURI` allocates string
        TokenUri(uri)
    }

    pub fn name(&self) -> String {
        let token_name_ptr = unsafe { PK11_GetTokenName(self.ptr as *mut _) };
        unsafe { CStr::from_ptr(token_name_ptr).to_string_lossy().to_string() }
    }

    /// Can read certificates without PIN
    pub fn is_friendly(&self) -> bool {
        (unsafe { PK11_IsFriendly(self.ptr as *mut _) }) > 0
    }

    /// Is a hardware token
    pub fn is_hw(&self) -> bool {
        (unsafe { PK11_IsHW(self.ptr as *mut _) }) > 0
    }

    /// Is an NSS internal token
    pub fn is_internal(&self) -> bool {
        (unsafe { PK11_IsInternal(self.ptr as *mut _) }) > 0
    }
}

pub struct TokenList<'a> {
    ptr: *mut PK11SlotList,
    _marker: PhantomData<&'a Nss>,
}

impl<'a> TokenList<'a> {
    pub fn iter(&'a self) -> TokenListIter<'a> {
        TokenListIter::new(self)
    }

    fn from_raw(ptr: *mut PK11SlotList) -> TokenList<'a> {
        TokenList {
            ptr,
            _marker: PhantomData,
        }
    }
}

impl<'a> Drop for TokenList<'a> {
    fn drop(&mut self) {
        unsafe { PK11_FreeSlotList(self.ptr) };
    }
}

pub struct TokenListIter<'a> {
    list: &'a TokenList<'a>,
    item_ptr: *mut PK11SlotListElement,
}

impl<'a> TokenListIter<'a> {
    fn new(list: &'a TokenList<'a>) -> TokenListIter<'a> {
        TokenListIter {
            list,
            item_ptr: unsafe { PK11_GetFirstSafe(list.ptr) },
        }
    }
}

impl<'a> Iterator for TokenListIter<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.item_ptr.is_null() {
            return None;
        }

        let token = Token::from_raw(unsafe { *self.item_ptr }.slot, false);

        self.item_ptr =
            unsafe { PK11_GetNextSafe(self.list.ptr as *mut _, self.item_ptr, PR_FALSE as i32) };

        Some(token)
    }
}

pub struct Cert<'a> {
    ptr: *const CERTCertificate,
    _marker: PhantomData<&'a Nss>,
}

impl<'a> Cert<'a> {
    fn from_raw(ptr: *const CERTCertificate) -> Cert<'a> {
        Cert {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn der(&self) -> SecItem {
        SecItem::new(&unsafe { *self.ptr }.derCert)
    }
}

pub struct CertList<'a> {
    ptr: *mut CERTCertList,
    _marker: PhantomData<&'a Nss>,
}

impl<'a> Drop for CertList<'a> {
    fn drop(&mut self) {
        unsafe {
            CERT_DestroyCertList(self.ptr);
        }
    }
}

impl<'a> CertList<'a> {
    pub fn iter(&'a self) -> CertListIter<'a> {
        CertListIter::new(self)
    }

    fn from_raw(ptr: *mut CERTCertList) -> CertList<'a> {
        CertList {
            ptr,
            _marker: PhantomData,
        }
    }

    fn list_ptr(&self) -> *const PRCList {
        unsafe { &raw const (*self.ptr).list }
    }

    fn is_end(&self, node_ptr: *const CERTCertListNode) -> bool {
        node_ptr.addr() == self.list_ptr().addr()
    }

    fn head_ptr(&self) -> Option<*const CERTCertListNode> {
        let node_ptr = unsafe { *self.list_ptr() }.next as *const CERTCertListNode;
        if self.is_end(node_ptr) {
            None
        } else {
            Some(node_ptr)
        }
    }

    fn next_ptr(&self, node_ptr: *const CERTCertListNode) -> Option<*const CERTCertListNode> {
        let node_ptr = unsafe { *node_ptr }.links.next as *const CERTCertListNode;
        if self.is_end(node_ptr) {
            None
        } else {
            Some(node_ptr)
        }
    }
}

pub struct CertListIter<'a> {
    list: &'a CertList<'a>,
    item_ptr: Option<*const CERTCertListNode>,
}

impl<'a> CertListIter<'a> {
    fn new(list: &'a CertList<'a>) -> CertListIter<'a> {
        CertListIter {
            list,
            item_ptr: list.head_ptr(),
        }
    }
}

impl<'a> Iterator for CertListIter<'a> {
    type Item = Cert<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let item_ptr = self.item_ptr?;
        self.item_ptr = self.list.next_ptr(item_ptr);
        Some(Cert::from_raw(unsafe { *item_ptr }.cert))
    }
}
