package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32        = syscall.NewLazyDLL("advapi32.dll")
	procRegSaveKeyW = advapi32.NewProc("RegSaveKeyW")
)

func main() {
	if err := enableBackupPrivilege(); err != nil {
		fmt.Printf("Failed to enable SeBackupPrivilege: %v\n", err)
		return
	}

	// Save SAM and SYSTEM registry keys
	files, err := saveRegFiles()
	if err != nil {
		fmt.Printf("Failed to save registry: %v\n", err)
		return
	}
	defer cleanupFiles(files)

	// Compress to tar.gz
	outputFile := "reg_backup_" + time.Now().Format("20060102150405") + ".tar.gz"
	if err := compressToTarGz(files, outputFile); err != nil {
		fmt.Printf("Compression failed: %v\n", err)
		return
	}

	fmt.Printf("Registry successfully saved and compressed to %s\n", outputFile)
}

// cleanupFiles deletes the specified files
func cleanupFiles(files []string) {
	for _, f := range files {
		os.Remove(f)
	}
}

// enableBackupPrivilege enables the SeBackupPrivilege privilege
func enableBackupPrivilege() error {
	var token windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	)
	if err != nil {
		return fmt.Errorf("Failed to open process token: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeBackupPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("Failed to lookup privilege value: %w", err)
	}

	privs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &privs, 0, nil, nil)
}

// RegSaveKey saves the registry key to a file
func RegSaveKey(hKey windows.Handle, filePath string) error {
	filePathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return fmt.Errorf("Failed to convert file path: %w", err)
	}

	ret, _, _ := procRegSaveKeyW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(filePathPtr)),
		uintptr(0),
	)

	if ret != uintptr(windows.ERROR_SUCCESS) {
		return fmt.Errorf("Failed to save registry key, error code 0x%x", ret)
	}
	return nil
}

// saveRegFiles saves the SAM and SYSTEM registry keys to files
func saveRegFiles() ([]string, error) {
	files := []string{"sam.hive", "system.hive"}
	regKeys := []string{"SAM", "SYSTEM"}

	for i, key := range regKeys {
		hKey, err := openRegKey(windows.HKEY_LOCAL_MACHINE, key, windows.KEY_READ|windows.KEY_WOW64_64KEY)
		if err != nil {
			return nil, fmt.Errorf("Failed to open %s: %w", key, err)
		}
		defer windows.RegCloseKey(hKey)

		if err := RegSaveKey(hKey, files[i]); err != nil {
			return nil, fmt.Errorf("Failed to save %s: %w", key, err)
		}
	}
	return files, nil
}

// openRegKey opens a registry key
func openRegKey(hive windows.Handle, path string, access uint32) (windows.Handle, error) {
	var hKey windows.Handle
	err := windows.RegOpenKeyEx(
		hive,
		windows.StringToUTF16Ptr(path),
		0,
		access,
		&hKey,
	)
	if err != nil {
		return 0, fmt.Errorf("Failed to open registry key: %w", err)
	}
	return hKey, nil
}

// compressToTarGz compresses files to tar.gz format
func compressToTarGz(sources []string, target string) error {
	file, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("Failed to create target file: %w", err)
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	for _, src := range sources {
		if err := addFileToTarWriter(src, tarWriter); err != nil {
			return err
		}
	}
	return nil
}

// addFileToTarWriter adds a file to the tar.Writer
func addFileToTarWriter(src string, tarWriter *tar.Writer) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("Failed to open source file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("Failed to get file info: %w", err)
	}

	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return fmt.Errorf("Failed to create file header: %w", err)
	}
	header.Name = filepath.Base(src)

	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("Failed to write file header: %w", err)
	}

	if _, err := io.Copy(tarWriter, f); err != nil {
		return fmt.Errorf("Failed to copy file content: %w", err)
	}
	return nil
}
