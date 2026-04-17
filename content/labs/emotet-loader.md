---
title: "emotet loader"
date: 2026-04-17
thread_id: "001"
sha256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
family: "emotet"
malware_type: "loader/dropper"
image: "img/labs/emotet-strings.png"
tags: ["emotet", "loader", "windows"]
replies:
  - id: "002"
    date: "2026-04-17"
    body: |
      **static analysis**

      packed with UPX, entropy 7.8. import table sparse — only `LoadLibraryA` and `GetProcAddress` visible pre-unpack. classic loader behavior, resolves everything at runtime.
  - id: "003"
    date: "2026-04-17"
    image: "img/labs/emotet-iat.png"
    body: |
      **dynamic analysis**

      drops copy to `%APPDATA%\Microsoft\Windows\somehost.exe`. registers run key at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. beacons out to hardcoded C2 every 60s.
  - id: "004"
    date: "2026-04-17"
    body: |
      **config extraction**

      XOR key at offset 0x1a4, key length 4 bytes. decrypted config contains 3 C2 IPs and a campaign ID. wrote extractor in Go — [repo link](#).
  - id: "005"
    date: "2026-04-17"
    body: |
      **IOCs**


      `sha256: a1b2c3...` \
      `C2: 192.168.1.1:443` \
      `C2: 10.0.0.1:8080` \
      `regkey: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\somehost`
---

initial triage. packed loader, drops and persists. full thread below.
