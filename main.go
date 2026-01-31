package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"
    "strconv"
    "time"
)

func main() {
    if len(os.Args) < 2 {
        printUsage()
        os.Exit(1)
    }

    switch os.Args[1] {
    case "server":
        serverCmd()
    case "client":
        clientCmd()
    default:
        printUsage()
        os.Exit(1)
    }
}

func printUsage() {
    fmt.Println("DFP - Debianrose's File Protocol")
    fmt.Println("Version: 3 (Virtual Disk Support)")
    fmt.Println("")
    fmt.Println("Server commands:")
    fmt.Println("  dfp server <port> [password]")
    fmt.Println("")
    fmt.Println("Client commands:")
    fmt.Println("  dfp client upload <server:port> <local_file> [remote_name]")
    fmt.Println("  dfp client download <server:port> <remote_file> [local_file]")
    fmt.Println("  dfp client list <server:port>")
    fmt.Println("  dfp client delete <server:port> <remote_file>")
    fmt.Println("  dfp client meta <server:port> <remote_file>")
    fmt.Println("  dfp client ping <server:port>")
    fmt.Println("")
    fmt.Println("Virtual Disk commands:")
    fmt.Println("  dfp client vdisk create <server:port> <name> <size_blocks> <block_size>")
    fmt.Println("  dfp client vdisk delete <server:port> <name>")
    fmt.Println("  dfp client vdisk list <server:port>")
    fmt.Println("  dfp client vdisk open <server:port> <name>")
    fmt.Println("  dfp client vdisk close <server:port> <name>")
    fmt.Println("  dfp client vdisk read <server:port> <name> <offset> <length> [output_file]")
    fmt.Println("  dfp client vdisk write <server:port> <name> <offset> <input_file>")
    fmt.Println("  dfp client vdisk stat <server:port> <name>")
    fmt.Println("")
    fmt.Println("Examples:")
    fmt.Println("  dfp server 5000 mypassword")
    fmt.Println("  dfp client upload 127.0.0.1:5000 file.txt")
    fmt.Println("  dfp client vdisk create 127.0.0.1:5000 mydisk 1024 4096")
    fmt.Println("  dfp client vdisk list 127.0.0.1:5000")
}

func serverCmd() {
    if len(os.Args) < 3 {
        fmt.Println("Error: port required")
        fmt.Println("Usage: dfp server <port> [password]")
        os.Exit(1)
    }

    port, err := strconv.ParseUint(os.Args[2], 10, 16)
    if err != nil {
        fmt.Printf("Error: invalid port: %v\n", err)
        os.Exit(1)
    }

    pass := "default_password"
    if len(os.Args) > 3 {
        pass = os.Args[3]
    }

    fmt.Printf("Starting DFP server on port %d...\n", port)
    fmt.Printf("Storage: %s\n", STORE_PATH)
    fmt.Printf("Protocol version: %d\n", PROTOCOL_VERSION)
    fmt.Printf("Virtual disks: enabled\n")
    fmt.Println("Press Ctrl+C to stop")

    handler, err := NewDFPHandler(pass, STORE_PATH)
    if err != nil {
        log.Fatalf("Failed to create handler: %v", err)
    }

    server := NewDFPServer(uint16(port), handler)

    if err := server.Run(); err != nil {
        log.Fatalf("Server error: %v", err)
    }
}

func clientCmd() {
    if len(os.Args) < 3 {
        fmt.Println("Error: client subcommand required")
        fmt.Println("Usage: dfp client <command> [args...]")
        os.Exit(1)
    }

    client := NewDFPClient()
    crypto := NewProtocolCrypto("default_password", nil)
    stats := &TransferStats{}

    switch os.Args[2] {
    case "upload":
        uploadCmd(client, crypto, stats)
    case "download":
        downloadCmd(client, crypto, stats)
    case "list":
        listCmd(client, crypto)
    case "delete":
        deleteCmd(client, stats)
    case "meta":
        metaCmd(client, crypto)
    case "ping":
        pingCmd(client)
    case "vdisk":
        vdiskCmd(client, crypto, stats)
    default:
        fmt.Printf("Error: unknown command '%s'\n", os.Args[2])
        os.Exit(1)
    }
}

func uploadCmd(client *DFPClient, crypto *ProtocolCrypto, stats *TransferStats) {
    if len(os.Args) < 5 {
        fmt.Println("Error: upload requires server address and file")
        fmt.Println("Usage: dfp client upload <server:port> <local_file> [remote_name]")
        os.Exit(1)
    }

    addr := os.Args[3]
    localFile := os.Args[4]

    remoteName := filepath.Base(localFile)
    if len(os.Args) > 5 {
        remoteName = os.Args[5]
    }

    fmt.Printf("Uploading %s to %s as %s...\n", localFile, addr, remoteName)
    start := time.Now()

    err := client.Upload(addr, localFile, remoteName, crypto, stats)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    duration := time.Since(start)
    speed := float64(stats.Bytes) / duration.Seconds() / 1024 / 1024

    fmt.Printf("✓ Upload completed in %v (%.2f MB/s)\n", duration.Round(time.Millisecond), speed)
    fmt.Printf("  Bytes: %d, Retries: %d, Errors: %d\n", stats.Bytes, stats.Retries, stats.Errors)
}

func downloadCmd(client *DFPClient, crypto *ProtocolCrypto, stats *TransferStats) {
    if len(os.Args) < 5 {
        fmt.Println("Error: download requires server address and file")
        fmt.Println("Usage: dfp client download <server:port> <remote_file> [local_file]")
        os.Exit(1)
    }

    addr := os.Args[3]
    remoteFile := os.Args[4]

    localFile := filepath.Join("downloads", remoteFile)
    if len(os.Args) > 5 {
        localFile = os.Args[5]
    }

    fmt.Printf("Downloading %s from %s to %s...\n", remoteFile, addr, localFile)
    start := time.Now()

    err := client.Download(addr, remoteFile, localFile, crypto, stats)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    duration := time.Since(start)
    speed := float64(stats.Bytes) / duration.Seconds() / 1024 / 1024

    fmt.Printf("✓ Download completed in %v (%.2f MB/s)\n", duration.Round(time.Millisecond), speed)
    fmt.Printf("  Bytes: %d, Retries: %d, Errors: %d\n", stats.Bytes, stats.Retries, stats.Errors)
}

func listCmd(client *DFPClient, crypto *ProtocolCrypto) {
    if len(os.Args) < 4 {
        fmt.Println("Error: list requires server address")
        fmt.Println("Usage: dfp client list <server:port>")
        os.Exit(1)
    }

    addr := os.Args[3]
    fmt.Printf("Listing files on %s...\n", addr)

    files, err := client.List(addr, crypto)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    if len(files) == 0 {
        fmt.Println("No files found")
        return
    }

    fmt.Printf("\nFound %d file(s):\n", len(files))
    fmt.Println("")
    fmt.Println("Name                          Size           Modified                  Version")
    fmt.Println("-------------------------------------------------------------------------------")

    for _, f := range files {
        size := formatBytes(f.Size)
        modified := f.Modified.Format("2006-01-02 15:04:05")

        fmt.Printf("%-30s %-15s %-25s v%d\n",
            truncate(f.Name, 28),
            size,
            modified,
            f.Version)
    }
}

func deleteCmd(client *DFPClient, stats *TransferStats) {
    if len(os.Args) < 5 {
        fmt.Println("Error: delete requires server address and file")
        fmt.Println("Usage: dfp client delete <server:port> <remote_file>")
        os.Exit(1)
    }

    addr := os.Args[3]
    remoteFile := os.Args[4]

    fmt.Printf("Deleting %s from %s...\n", remoteFile, addr)

    err := client.Delete(addr, remoteFile, stats)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("✓ File deleted successfully")
}

func metaCmd(client *DFPClient, crypto *ProtocolCrypto) {
    if len(os.Args) < 5 {
        fmt.Println("Error: meta requires server address and file")
        fmt.Println("Usage: dfp client meta <server:port> <remote_file>")
        os.Exit(1)
    }

    addr := os.Args[3]
    remoteFile := os.Args[4]

    fmt.Printf("Getting metadata for %s from %s...\n", remoteFile, addr)

    meta, err := client.GetMetadata(addr, remoteFile, crypto)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("\nFile Metadata:")
    fmt.Println("--------------")
    fmt.Printf("Name:      %s\n", meta.Name)
    fmt.Printf("Size:      %s (%d bytes)\n", formatBytes(meta.Size), meta.Size)
    fmt.Printf("Modified:  %s\n", meta.Modified.Format("2006-01-02 15:04:05"))
    fmt.Printf("Encrypted: %v\n", meta.Encrypted)
    fmt.Printf("Compressed: %v\n", meta.Compressed)
    fmt.Printf("Version:   v%d\n", meta.Version)
    fmt.Printf("Checksum:  %x\n", meta.Checksum[:8])
}

func pingCmd(client *DFPClient) {
    if len(os.Args) < 4 {
        fmt.Println("Error: ping requires server address")
        fmt.Println("Usage: dfp client ping <server:port>")
        os.Exit(1)
    }

    addr := os.Args[3]
    fmt.Printf("Pinging %s... ", addr)

    duration, err := client.Ping(addr)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("✓ Response time: %v\n", duration.Round(time.Millisecond))
}

func vdiskCmd(client *DFPClient, crypto *ProtocolCrypto, stats *TransferStats) {
    if len(os.Args) < 4 {
        fmt.Println("Error: vdisk subcommand required")
        fmt.Println("Usage: dfp client vdisk <command> [args...]")
        os.Exit(1)
    }

    switch os.Args[3] {
    case "create":
        vdiskCreateCmd(client, stats)
    case "delete":
        vdiskDeleteCmd(client, stats)
    case "list":
        vdiskListCmd(client, crypto)
    case "open":
        vdiskOpenCmd(client, stats)
    case "close":
        vdiskCloseCmd(client, stats)
    case "read":
        vdiskReadCmd(client, stats)
    case "write":
        vdiskWriteCmd(client, stats)
    case "stat":
        vdiskStatCmd(client, crypto)
    default:
        fmt.Printf("Error: unknown vdisk command '%s'\n", os.Args[3])
        os.Exit(1)
    }
}

func vdiskCreateCmd(client *DFPClient, stats *TransferStats) {
    if len(os.Args) < 8 {
        fmt.Println("Error: vdisk create requires server, name, size and block size")
        fmt.Println("Usage: dfp client vdisk create <server:port> <name> <size_blocks> <block_size>")
        os.Exit(1)
    }

    addr := os.Args[4]
    name := os.Args[5]
    size, err := strconv.ParseUint(os.Args[6], 10, 32)
    if err != nil {
        fmt.Printf("Error: invalid size: %v\n", err)
        os.Exit(1)
    }
    blockSize, err := strconv.ParseUint(os.Args[7], 10, 32)
    if err != nil {
        fmt.Printf("Error: invalid block size: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Creating virtual disk '%s' on %s...\n", name, addr)

    err = client.DiskCreate(addr, name, uint32(size), uint32(blockSize), stats)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    totalSize := size * blockSize
    fmt.Printf("✓ Virtual disk created successfully\n")
    fmt.Printf("  Name: %s, Size: %s (%d blocks x %d bytes)\n",
        name, formatBytes(int64(totalSize)), size, blockSize)
}

func vdiskDeleteCmd(client *DFPClient, stats *TransferStats) {
    if len(os.Args) < 6 {
        fmt.Println("Error: vdisk delete requires server and name")
        fmt.Println("Usage: dfp client vdisk delete <server:port> <name>")
        os.Exit(1)
    }

    addr := os.Args[4]
    name := os.Args[5]

    fmt.Printf("Deleting virtual disk '%s' from %s...\n", name, addr)

    err := client.DiskDelete(addr, name, stats)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("✓ Virtual disk deleted successfully")
}

func vdiskListCmd(client *DFPClient, crypto *ProtocolCrypto) {
    if len(os.Args) < 5 {
        fmt.Println("Error: vdisk list requires server address")
        fmt.Println("Usage: dfp client vdisk list <server:port>")
        os.Exit(1)
    }

    addr := os.Args[4]
    fmt.Printf("Listing virtual disks on %s...\n", addr)

    disks, err := client.DiskList(addr, crypto)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    if len(disks) == 0 {
        fmt.Println("No virtual disks found")
        return
    }

    fmt.Printf("\nFound %d virtual disk(s):\n", len(disks))
    fmt.Println("")
    fmt.Println("Name                          Size           Block Size   Used          Created                 Open")
    fmt.Println("------------------------------------------------------------------------------------------------------")

    for _, d := range disks {
        size := formatBytes(d.Size)
        used := formatBytes(d.Used)
        blockSize := formatBytes(int64(d.BlockSize))
        created := d.Created.Format("2006-01-02 15:04:05")

        fmt.Printf("%-30s %-15s %-12s %-15s %-22s %v\n",
            truncate(d.Name, 28),
            size,
            blockSize,
            used,
            created,
            d.Flags&0x01 != 0)
    }
}

func vdiskOpenCmd(client *DFPClient, stats *TransferStats) {
    if len(os.Args) < 6 {
        fmt.Println("Error: vdisk open requires server and name")
        fmt.Println("Usage: dfp client vdisk open <server:port> <name>")
        os.Exit(1)
    }

    addr := os.Args[4]
    name := os.Args[5]

    fmt.Printf("Opening virtual disk '%s' on %s...\n", name, addr)

    err := client.DiskOpen(addr, name, stats)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("✓ Virtual disk opened successfully")
}

func vdiskCloseCmd(client *DFPClient, stats *TransferStats) {
    if len(os.Args) < 6 {
        fmt.Println("Error: vdisk close requires server and name")
        fmt.Println("Usage: dfp client vdisk close <server:port> <name>")
        os.Exit(1)
    }

    addr := os.Args[4]
    name := os.Args[5]

    fmt.Printf("Closing virtual disk '%s' on %s...\n", name, addr)

    err := client.DiskClose(addr, name, stats)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("✓ Virtual disk closed successfully")
}

func vdiskReadCmd(client *DFPClient, stats *TransferStats) {
    if len(os.Args) < 8 {
        fmt.Println("Error: vdisk read requires server, name, offset and length")
        fmt.Println("Usage: dfp client vdisk read <server:port> <name> <offset> <length> [output_file]")
        os.Exit(1)
    }

    addr := os.Args[4]
    name := os.Args[5]
    offset, err := strconv.ParseUint(os.Args[6], 10, 64)
    if err != nil {
        fmt.Printf("Error: invalid offset: %v\n", err)
        os.Exit(1)
    }
    length, err := strconv.ParseUint(os.Args[7], 10, 64)
    if err != nil {
        fmt.Printf("Error: invalid length: %v\n", err)
        os.Exit(1)
    }

    outputFile := ""
    if len(os.Args) > 8 {
        outputFile = os.Args[8]
    }

    fmt.Printf("Reading %d bytes from offset %d of virtual disk '%s' on %s...\n",
        length, offset, name, addr)
    start := time.Now()

    data, err := client.DiskRead(addr, name, offset, length, stats)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    duration := time.Since(start)
    speed := float64(stats.Bytes) / duration.Seconds() / 1024 / 1024

    if outputFile != "" {
        os.MkdirAll(filepath.Dir(outputFile), 0755)
        if err := os.WriteFile(outputFile, data, 0644); err != nil {
            fmt.Printf("Error writing to file: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("✓ Read completed in %v (%.2f MB/s), saved to %s\n",
            duration.Round(time.Millisecond), speed, outputFile)
    } else {
        fmt.Printf("✓ Read completed in %v (%.2f MB/s)\n",
            duration.Round(time.Millisecond), speed)
        fmt.Printf("  Bytes: %d, Retries: %d, Errors: %d\n",
            stats.Bytes, stats.Retries, stats.Errors)
    }
}

func vdiskWriteCmd(client *DFPClient, stats *TransferStats) {
    if len(os.Args) < 8 {
        fmt.Println("Error: vdisk write requires server, name, offset and input file")
        fmt.Println("Usage: dfp client vdisk write <server:port> <name> <offset> <input_file>")
        os.Exit(1)
    }

    addr := os.Args[4]
    name := os.Args[5]
    offset, err := strconv.ParseUint(os.Args[6], 10, 64)
    if err != nil {
        fmt.Printf("Error: invalid offset: %v\n", err)
        os.Exit(1)
    }
    inputFile := os.Args[7]

    fmt.Printf("Writing to offset %d of virtual disk '%s' on %s from %s...\n",
        offset, name, addr, inputFile)
    start := time.Now()

    data, err := os.ReadFile(inputFile)
    if err != nil {
        fmt.Printf("Error reading input file: %v\n", err)
        os.Exit(1)
    }

    err = client.DiskWrite(addr, name, offset, data, stats)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    duration := time.Since(start)
    speed := float64(stats.Bytes) / duration.Seconds() / 1024 / 1024

    fmt.Printf("✓ Write completed in %v (%.2f MB/s)\n",
        duration.Round(time.Millisecond), speed)
    fmt.Printf("  Bytes: %d, Retries: %d, Errors: %d\n",
        stats.Bytes, stats.Retries, stats.Errors)
}

func vdiskStatCmd(client *DFPClient, crypto *ProtocolCrypto) {
    if len(os.Args) < 6 {
        fmt.Println("Error: vdisk stat requires server and name")
        fmt.Println("Usage: dfp client vdisk stat <server:port> <name>")
        os.Exit(1)
    }

    addr := os.Args[4]
    name := os.Args[5]

    fmt.Printf("Getting statistics for virtual disk '%s' on %s...\n", name, addr)

    meta, err := client.DiskStat(addr, name, crypto)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("\nVirtual Disk Statistics:")
    fmt.Println("-----------------------")
    fmt.Printf("Name:       %s\n", meta.Name)
    fmt.Printf("Size:       %s (%d bytes)\n", formatBytes(meta.Size), meta.Size)
    fmt.Printf("Block Size: %d bytes\n", meta.BlockSize)
    fmt.Printf("Used:       %s (%d bytes, %.1f%%)\n",
        formatBytes(meta.Used), meta.Used, float64(meta.Used)/float64(meta.Size)*100)
    fmt.Printf("Created:    %s\n", meta.Created.Format("2006-01-02 15:04:05"))
    fmt.Printf("Modified:   %s\n", meta.Modified.Format("2006-01-02 15:04:05"))
    fmt.Printf("Version:    v%d\n", meta.Version)
    fmt.Printf("Flags:      0x%08X\n", meta.Flags)
}

func formatBytes(b int64) string {
    const unit = 1024
    if b < unit {
        return fmt.Sprintf("%d B", b)
    }
    div, exp := int64(unit), 0
    for n := b / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func truncate(s string, maxLen int) string {
    if len(s) <= maxLen {
        return s
    }
    return s[:maxLen-3] + "..."
}
