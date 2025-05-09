#[cfg(target_os = "windows")]
use std::{
    ffi::OsStr,
    io,
    ops::{Deref, DerefMut},
    os::windows::ffi::OsStrExt,
    ptr::null_mut,
    result::Result,
};
#[cfg(target_os = "windows")]
use winapi::{
    shared::{
        guiddef::{GUID, LPGUID},
        minwindef::{BOOL, DWORD, FALSE, HMODULE, MAX_PATH, PBOOL, PDWORD, TRUE},
        ntdef::{HANDLE, LPCWSTR, NULL, PCWSTR, PVOID, PWSTR},
        windef::HWND,
        winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS},
    },
    um::{
        cfgmgr32::{CM_Get_Device_ID_ExW, CR_SUCCESS},
        fileapi::{CreateFileW, OPEN_EXISTING},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        ioapiset::DeviceIoControl,
        libloaderapi::{GetProcAddress, LoadLibraryA},
        setupapi::*,
        winnt::{GENERIC_READ, GENERIC_WRITE}, wow64apiset::{Wow64DisableWow64FsRedirection, Wow64RevertWow64FsRedirection},
    },
};

#[cfg(target_os = "windows")]
#[link(name = "Newdev")]
extern "system" {
    fn UpdateDriverForPlugAndPlayDevicesW(
        hwnd_parent: HWND,
        hardware_id: LPCWSTR,
        full_inf_path: LPCWSTR,
        install_flags: DWORD,
        b_reboot_required: PBOOL,
    ) -> BOOL;
}

#[cfg(target_os = "windows")]
#[derive(thiserror::Error, Debug)]
pub enum DeviceError {
    #[error("Failed to call {0}, {1:?}")]
    WinApiLastErr(String, io::Error),
    #[error("Failed to call {0}, returns {1}")]
    WinApiErrCode(String, DWORD),
    #[error("{0}")]
    Raw(String),
}

#[cfg(target_os = "windows")]
struct DeviceInfo(HDEVINFO);

#[cfg(target_os = "windows")]
impl DeviceInfo {
    fn setup_di_create_device_info_list(class_guid: &mut GUID) -> Result<Self, DeviceError> {
        let dev_info = unsafe { SetupDiCreateDeviceInfoList(class_guid, null_mut()) };
        if dev_info == null_mut() {
            return Err(DeviceError::WinApiLastErr(
                "SetupDiCreateDeviceInfoList".to_string(),
                io::Error::last_os_error(),
            ));
        }

        Ok(Self(dev_info))
    }

    fn setup_di_get_class_devs_ex_w(
        class_guid: *const GUID,
        flags: DWORD,
    ) -> Result<Self, DeviceError> {
        let dev_info = unsafe {
            SetupDiGetClassDevsExW(
                class_guid,
                null_mut(),
                null_mut(),
                flags,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if dev_info == null_mut() {
            return Err(DeviceError::WinApiLastErr(
                "SetupDiGetClassDevsExW".to_string(),
                io::Error::last_os_error(),
            ));
        }
        Ok(Self(dev_info))
    }
}

#[cfg(target_os = "windows")]
impl Drop for DeviceInfo {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

#[cfg(target_os = "windows")]
impl Deref for DeviceInfo {
    type Target = HDEVINFO;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(target_os = "windows")]
impl DerefMut for DeviceInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(target_os = "windows")]
pub unsafe fn install_driver(
    inf_path: &str,
    hardware_id: &str,
    reboot_required: &mut bool,
) -> Result<(), DeviceError> {
    let driver_inf_path = OsStr::new(inf_path)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect::<Vec<u16>>();
    let hardware_id = OsStr::new(hardware_id)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect::<Vec<u16>>();

    let mut class_guid: GUID = std::mem::zeroed();
    let mut class_name: [u16; 32] = [0; 32];

    if SetupDiGetINFClassW(
        driver_inf_path.as_ptr(),
        &mut class_guid,
        class_name.as_mut_ptr(),
        class_name.len() as _,
        null_mut(),
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiGetINFClassW".to_string(),
            io::Error::last_os_error(),
        ));
    }

    let dev_info = DeviceInfo::setup_di_create_device_info_list(&mut class_guid)?;

    let mut dev_info_data = SP_DEVINFO_DATA {
        cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as _,
        ClassGuid: class_guid,
        DevInst: 0,
        Reserved: 0,
    };
    if SetupDiCreateDeviceInfoW(
        *dev_info,
        class_name.as_ptr(),
        &class_guid,
        null_mut(),
        null_mut(),
        DICD_GENERATE_ID,
        &mut dev_info_data,
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiCreateDeviceInfoW".to_string(),
            io::Error::last_os_error(),
        ));
    }

    if SetupDiSetDeviceRegistryPropertyW(
        *dev_info,
        &mut dev_info_data,
        SPDRP_HARDWAREID,
        hardware_id.as_ptr() as _,
        (hardware_id.len() * 2) as _,
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiSetDeviceRegistryPropertyW".to_string(),
            io::Error::last_os_error(),
        ));
    }

    if SetupDiCallClassInstaller(DIF_REGISTERDEVICE, *dev_info, &mut dev_info_data) == FALSE {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiCallClassInstaller".to_string(),
            io::Error::last_os_error(),
        ));
    }

    let mut reboot_required_ = FALSE;
    if UpdateDriverForPlugAndPlayDevicesW(
        null_mut(),
        hardware_id.as_ptr(),
        driver_inf_path.as_ptr(),
        1,
        &mut reboot_required_,
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "UpdateDriverForPlugAndPlayDevicesW".to_string(),
            io::Error::last_os_error(),
        ));
    }
    println!("UpdateDriverForPlugAndPlayDevicesW: 2");
    *reboot_required = reboot_required_ == TRUE;

    Ok(())
}

#[cfg(target_os = "windows")]
pub unsafe fn install_driver_64(
    inf_path: &str,
    hardware_id: &str,
    reboot_required: &mut bool,
) -> Result<(), DeviceError> {
    let driver_inf_path = OsStr::new(inf_path)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect::<Vec<u16>>();
    let hardware_id = OsStr::new(hardware_id)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect::<Vec<u16>>();

    let setupapi: HMODULE =
        unsafe { LoadLibraryA(b"C:\\Windows\\System32\\setupapi.dll\0".as_ptr() as _) };
    if setupapi.is_null() {
        return Err(DeviceError::Raw("Failed to load setupapi.dll".to_string()));
    }

    type FnSetupDiGetINFClassW = fn(
        InfName: PCWSTR,
        ClassGuid: LPGUID,
        ClassName: PWSTR,
        ClassNameSize: DWORD,
        RequiredSize: PDWORD,
    ) -> BOOL;
    let setup_di_get_inf_class_w: FnSetupDiGetINFClassW = unsafe {
        let function_name = b"SetupDiGetINFClassW\0";
        let function_ptr = GetProcAddress(setupapi, function_name.as_ptr() as _);
        std::mem::transmute(function_ptr)
    };

    println!("setup_di_get_inf_class_w, {:p}", setup_di_get_inf_class_w);

    let mut class_guid: GUID = std::mem::zeroed();
    let mut class_name: [u16; 32] = [0; 32];

    if setup_di_get_inf_class_w(
        driver_inf_path.as_ptr(),
        &mut class_guid,
        class_name.as_mut_ptr(),
        class_name.len() as _,
        null_mut(),
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiGetINFClassW".to_string(),
            io::Error::last_os_error(),
        ));
    }

    // let dev_info = DeviceInfo::setup_di_create_device_info_list(&mut class_guid)?;

    type FnSetupDiCreateDeviceInfoList = fn(ClassGuid: LPGUID, hwndParent: HWND) -> HDEVINFO;
    let setup_di_create_device_info_list: FnSetupDiCreateDeviceInfoList = unsafe {
        let function_name = b"SetupDiCreateDeviceInfoList\0";
        let function_ptr = GetProcAddress(setupapi, function_name.as_ptr() as _);
        std::mem::transmute(function_ptr)
    };
    println!(
        "setup_di_create_device_info_list: 1, {:p}",
        setup_di_create_device_info_list
    );

    let dev_info = {
        let dev_info = { setup_di_create_device_info_list(&mut class_guid, null_mut()) };
        if dev_info == null_mut() {
            return Err(DeviceError::WinApiLastErr(
                "SetupDiCreateDeviceInfoList".to_string(),
                io::Error::last_os_error(),
            ));
        }
        DeviceInfo(dev_info)
    };

    type FnSetupDiCreateDeviceInfoW = fn(
        DeviceInfoSet: HDEVINFO,
        DeviceName: PCWSTR,
        ClassGuid: LPGUID,
        DeviceDescription: PCWSTR,
        hwndParent: HWND,
        CreationFlags: DWORD,
        DeviceInfoData: PSP_DEVINFO_DATA,
    ) -> BOOL;

    let setup_di_create_device_info_w: FnSetupDiCreateDeviceInfoW = unsafe {
        let function_name = b"SetupDiCreateDeviceInfoW\0";
        let function_ptr = GetProcAddress(setupapi, function_name.as_ptr() as _);
        std::mem::transmute(function_ptr)
    };
    println!(
        "setup_di_create_device_info_w: 1, {:p}",
        setup_di_create_device_info_w
    );

    let mut dev_info_data = SP_DEVINFO_DATA {
        cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as _,
        ClassGuid: class_guid,
        DevInst: 0,
        Reserved: 0,
    };
    if setup_di_create_device_info_w(
        *dev_info,
        class_name.as_ptr(),
        &mut class_guid,
        null_mut(),
        null_mut(),
        DICD_GENERATE_ID,
        &mut dev_info_data,
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiCreateDeviceInfoW".to_string(),
            io::Error::last_os_error(),
        ));
    }

    type FnSetupDiSetDeviceRegistryPropertyW = fn(
        DeviceInfoSet: HDEVINFO,
        DeviceInfoData: PSP_DEVINFO_DATA,
        Property: DWORD,
        PropertyBuffer: *const u16,
        PropertyBufferSize: DWORD,
    ) -> BOOL;

    let setup_di_set_device_registry_property_w: FnSetupDiSetDeviceRegistryPropertyW = unsafe {
        let function_name = b"SetupDiSetDeviceRegistryPropertyW\0";
        let function_ptr = GetProcAddress(setupapi, function_name.as_ptr() as _);
        std::mem::transmute(function_ptr)
    };
    println!(
        "setup_di_set_device_registry_property_w: 1, {:p}",
        setup_di_set_device_registry_property_w
    );

    if setup_di_set_device_registry_property_w(
        *dev_info,
        &mut dev_info_data,
        SPDRP_HARDWAREID,
        hardware_id.as_ptr() as _,
        (hardware_id.len() * 2) as _,
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiSetDeviceRegistryPropertyW".to_string(),
            io::Error::last_os_error(),
        ));
    }

    type FnSetupDiCallClassInstaller = fn(
        InstallFunction: DI_FUNCTION,
        DeviceInfoSet: HDEVINFO,
        DeviceInfoData: PSP_DEVINFO_DATA,
    ) -> BOOL;
    let setup_di_call_class_installer: FnSetupDiCallClassInstaller = unsafe {
        let function_name = b"SetupDiCallClassInstaller\0";
        let function_ptr = GetProcAddress(setupapi, function_name.as_ptr() as _);
        std::mem::transmute(function_ptr)
    };
    println!(
        "setup_di_call_class_installer: 1, {:p}",
        setup_di_call_class_installer
    );

    if SetupDiCallClassInstaller(DIF_REGISTERDEVICE, *dev_info, &mut dev_info_data) == FALSE {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiCallClassInstaller".to_string(),
            io::Error::last_os_error(),
        ));
    }

    let newdev: HMODULE =
        unsafe { LoadLibraryA(b"C:\\Windows\\System32\\newdev.dll\0".as_ptr() as _) };
    if newdev.is_null() {
        return Err(DeviceError::Raw("Failed to load newdev.dll".to_string()));
    }

    type FnUpdateDriverForPlugAndPlayDevicesW = fn(
        hwnd_parent: HWND,
        hardware_id: LPCWSTR,
        full_inf_path: LPCWSTR,
        install_flags: DWORD,
        b_reboot_required: PBOOL,
    ) -> BOOL;
    let update_driver_for_plug_and_play_devices_w: FnUpdateDriverForPlugAndPlayDevicesW = unsafe {
        let function_name = b"UpdateDriverForPlugAndPlayDevicesW\0";
        let function_ptr = GetProcAddress(newdev, function_name.as_ptr() as _);
        std::mem::transmute(function_ptr)
    };
    println!(
        "update_driver_for_plug_and_play_devices_w: 1, {:p}",
        update_driver_for_plug_and_play_devices_w
    );

    let mut reboot_required_ = FALSE;
    if update_driver_for_plug_and_play_devices_w(
        null_mut(),
        hardware_id.as_ptr(),
        driver_inf_path.as_ptr(),
        1,
        &mut reboot_required_,
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "UpdateDriverForPlugAndPlayDevicesW".to_string(),
            io::Error::last_os_error(),
        ));
    }
    println!("UpdateDriverForPlugAndPlayDevicesW: 2");
    *reboot_required = reboot_required_ == TRUE;

    Ok(())
}

#[cfg(target_os = "windows")]
unsafe fn is_same_hardware_id(
    dev_info: &DeviceInfo,
    devinfo_data: &mut SP_DEVINFO_DATA,
    hardware_id: &str,
) -> Result<bool, DeviceError> {
    let mut cur_hardware_id = [0u16; 1024];
    if SetupDiGetDeviceRegistryPropertyW(
        **dev_info,
        devinfo_data,
        SPDRP_HARDWAREID,
        null_mut(),
        cur_hardware_id.as_mut_ptr() as _,
        cur_hardware_id.len() as _,
        null_mut(),
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiGetDeviceRegistryPropertyW".to_string(),
            io::Error::last_os_error(),
        ));
    }

    let cur_hardware_id = String::from_utf16_lossy(&cur_hardware_id)
        .trim_end_matches(char::from(0))
        .to_string();
    Ok(cur_hardware_id == hardware_id)
}

#[cfg(target_os = "windows")]
pub unsafe fn uninstall_driver(
    hardware_id: &str,
    reboot_required: &mut bool,
) -> Result<(), DeviceError> {
    let dev_info =
        DeviceInfo::setup_di_get_class_devs_ex_w(null_mut(), DIGCF_ALLCLASSES | DIGCF_PRESENT)?;

    let mut device_info_list_detail = SP_DEVINFO_LIST_DETAIL_DATA_W {
        cbSize: std::mem::size_of::<SP_DEVINFO_LIST_DETAIL_DATA_W>() as _,
        ClassGuid: std::mem::zeroed(),
        RemoteMachineHandle: null_mut(),
        RemoteMachineName: [0; SP_MAX_MACHINENAME_LENGTH],
    };
    if SetupDiGetDeviceInfoListDetailW(*dev_info, &mut device_info_list_detail) == FALSE {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiGetDeviceInfoListDetailW".to_string(),
            io::Error::last_os_error(),
        ));
    }

    let mut devinfo_data = SP_DEVINFO_DATA {
        cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as _,
        ClassGuid: std::mem::zeroed(),
        DevInst: 0,
        Reserved: 0,
    };

    let mut device_index = 0;
    loop {
        if SetupDiEnumDeviceInfo(*dev_info, device_index, &mut devinfo_data) == FALSE {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as _) {
                break;
            }
            return Err(DeviceError::WinApiLastErr(
                "SetupDiEnumDeviceInfo".to_string(),
                err,
            ));
        }

        let mut device_id = [0; SP_MAX_MACHINENAME_LENGTH];
        let r = CM_Get_Device_ID_ExW(
            devinfo_data.DevInst,
            device_id.as_mut_ptr(),
            SP_MAX_MACHINENAME_LENGTH as _,
            0,
            device_info_list_detail.RemoteMachineHandle,
        );
        if r != CR_SUCCESS {
            return Err(DeviceError::WinApiErrCode(
                "CM_Get_Device_ID_Ex".to_string(),
                r,
            ));
        }

        match is_same_hardware_id(&dev_info, &mut devinfo_data, hardware_id) {
            Ok(false) => {
                device_index += 1;
                continue;
            }
            Err(e) => {
                log::error!("Failed to call is_same_hardware_id, {:?}", e);
                device_index += 1;
                continue;
            }
            _ => {}
        }

        let mut remove_device_params = SP_REMOVEDEVICE_PARAMS {
            ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as _,
                InstallFunction: DIF_REMOVE,
            },
            Scope: DI_REMOVEDEVICE_GLOBAL,
            HwProfile: 0,
        };

        if SetupDiSetClassInstallParamsW(
            *dev_info,
            &mut devinfo_data,
            &mut remove_device_params.ClassInstallHeader,
            std::mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as _,
        ) == FALSE
        {
            return Err(DeviceError::WinApiLastErr(
                "SetupDiSetClassInstallParams".to_string(),
                io::Error::last_os_error(),
            ));
        }

        if SetupDiCallClassInstaller(DIF_REMOVE, *dev_info, &mut devinfo_data) == FALSE {
            return Err(DeviceError::WinApiLastErr(
                "SetupDiCallClassInstaller".to_string(),
                io::Error::last_os_error(),
            ));
        }

        let mut device_params = SP_DEVINSTALL_PARAMS_W {
            cbSize: std::mem::size_of::<SP_DEVINSTALL_PARAMS_W>() as _,
            Flags: 0,
            FlagsEx: 0,
            hwndParent: null_mut(),
            InstallMsgHandler: None,
            InstallMsgHandlerContext: null_mut(),
            FileQueue: null_mut(),
            ClassInstallReserved: 0,
            Reserved: 0,
            DriverPath: [0; MAX_PATH],
        };

        if SetupDiGetDeviceInstallParamsW(*dev_info, &mut devinfo_data, &mut device_params) == FALSE
        {
            log::error!(
                "Failed to call SetupDiGetDeviceInstallParamsW, {:?}",
                io::Error::last_os_error()
            );
        } else {
            if device_params.Flags & (DI_NEEDRESTART | DI_NEEDREBOOT) != 0 {
                *reboot_required = true;
            }
        }

        device_index += 1;
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub unsafe fn plug_monitor(interface_guid: &GUID, add: bool) -> Result<bool, DeviceError> {
    let h_device = match open_device_handle(interface_guid) {
        Ok(h) => h,
        Err(e) => {
            if let DeviceError::WinApiLastErr(_, e2) = &e {
                if e2.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as _) {
                    return Ok(false);
                }
            }
            return Err(e);
        }
    };
    let cmd = if add { 0x10 } else { 0x00 };
    let cmd = [cmd, 0x00, 0x00, 0x00];
    let mut bytes_returned = 0;
    let result = DeviceIoControl(
        h_device,
        2307084,
        cmd.as_ptr() as _,
        cmd.len() as _,
        null_mut(),
        0,
        &mut bytes_returned,
        null_mut(),
    );
    CloseHandle(h_device);
    if result == FALSE {
        return Err(DeviceError::WinApiLastErr(
            "DeviceIoControl".to_string(),
            io::Error::last_os_error(),
        ));
    }
    Ok(true)
}

#[cfg(target_os = "windows")]
unsafe fn get_device_path(interface_guid: &GUID) -> Result<Vec<u16>, DeviceError> {
    let dev_info = DeviceInfo::setup_di_get_class_devs_ex_w(
        interface_guid,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
    )?;
    let mut device_interface_data = SP_DEVICE_INTERFACE_DATA {
        cbSize: std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as _,
        InterfaceClassGuid: *interface_guid,
        Flags: 0,
        Reserved: 0,
    };
    if SetupDiEnumDeviceInterfaces(
        *dev_info,
        null_mut(),
        interface_guid,
        0,
        &mut device_interface_data,
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiEnumDeviceInterfaces".to_string(),
            io::Error::last_os_error(),
        ));
    }

    let mut required_length = 0;
    if SetupDiGetDeviceInterfaceDetailW(
        *dev_info,
        &mut device_interface_data,
        null_mut(),
        0,
        &mut required_length,
        null_mut(),
    ) == FALSE
    {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as _) {
            return Err(DeviceError::WinApiLastErr(
                "SetupDiGetDeviceInterfaceDetailW".to_string(),
                err,
            ));
        }
    }

    let predicted_length = required_length;
    let mut vec_data: Vec<u8> = Vec::with_capacity(required_length as _);
    let device_interface_detail_data = vec_data.as_mut_ptr();
    let device_interface_detail_data =
        device_interface_detail_data as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
    (*device_interface_detail_data).cbSize =
        std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as _;
    if SetupDiGetDeviceInterfaceDetailW(
        *dev_info,
        &mut device_interface_data,
        device_interface_detail_data,
        predicted_length,
        &mut required_length,
        null_mut(),
    ) == FALSE
    {
        return Err(DeviceError::WinApiLastErr(
            "SetupDiGetDeviceInterfaceDetailW".to_string(),
            io::Error::last_os_error(),
        ));
    }

    let mut path = Vec::new();
    let device_path_ptr =
        std::ptr::addr_of!((*device_interface_detail_data).DevicePath) as *const u16;
    let steps = device_path_ptr as usize - vec_data.as_ptr() as usize;
    for i in 0..(predicted_length - steps as u32) / 2 {
        if *device_path_ptr.offset(i as _) == 0 {
            path.push(0);
            break;
        }
        path.push(*device_path_ptr.offset(i as _));
    }
    Ok(path)
}

#[cfg(target_os = "windows")]
unsafe fn open_device_handle(interface_guid: &GUID) -> Result<HANDLE, DeviceError> {
    let device_path = get_device_path(interface_guid)?;
    println!("device_path: {:?}", String::from_utf16_lossy(&device_path));
    let h_device = CreateFileW(
        device_path.as_ptr(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        null_mut(),
        OPEN_EXISTING,
        0,
        null_mut(),
    );
    if h_device == INVALID_HANDLE_VALUE || h_device == NULL {
        return Err(DeviceError::WinApiLastErr(
            "CreateFileW".to_string(),
            io::Error::last_os_error(),
        ));
    }
    Ok(h_device)
}

#[cfg(target_os = "windows")]
fn main() {

    let mut old_wow64_value: PVOID = null_mut();
    unsafe {
        if Wow64DisableWow64FsRedirection(&mut old_wow64_value) == FALSE {
            println!("Failed to call Wow64DisableWow64FsRedirection, {:?}", io::Error::last_os_error());
        }
    }

    println!("Install driver: {:?}", unsafe {
        install_driver(r#"D:\usbmmidd_v2\usbmmIdd.inf"#, "usbmmidd", &mut false)
    });

    unsafe {
        if Wow64RevertWow64FsRedirection(old_wow64_value) == FALSE {
            println!("Failed to call Wow64RevertWow64FsRedirection, {:?}", io::Error::last_os_error());
        }
    }

    std::thread::sleep(std::time::Duration::from_secs(3));

    //{781EF630-72B2-11d2-B852-00C04EAF5272}
    let interface_guid = &GUID {
        Data1: 0xb5ffd75f,
        Data2: 0xda40,
        Data3: 0x4353,
        Data4: [0x8f, 0xf8, 0xb6, 0xda, 0xf6, 0xf1, 0xd8, 0xca],
    };

    println!("Plug in monitor: {:?}", unsafe {
        plug_monitor(&interface_guid, true)
    });

    std::thread::sleep(std::time::Duration::from_secs(3));

    println!("Plug out monitor: {:?}", unsafe {
        plug_monitor(&interface_guid, true)
    });

    std::thread::sleep(std::time::Duration::from_secs(3));

    println!("Uninstall driver: {:?}", unsafe {
        uninstall_driver("usbmmidd", &mut false)
    });
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("Only available on Windows OS.");
}
