# 🚀 NITPANEL

Web server management panel for **AlmaLinux / Rocky Linux / RHEL 9+** — Nginx, MySQL, PHP-FPM (7.4 → 8.4), Certbot SSL, Fail2ban, phpMyAdmin, File Manager.

Written in **Rust + Actix-web 4** → lightweight, fast, single binary.

---

## ⚡ One-line installation

```bash

curl -fsSL https://raw.githubusercontent.com/trongthangno9-nitpanel/nitpanel/main/one-line-install.sh | sudo bash
```

Completes in ~30 seconds if the binary is available, or ~5-10 minutes if built from source.

After installation:
- 🌐 Access panel: `http://<IP-VPS>:8765`
- 🔑 Password: saved at `/etc/nitpanel/credentials.txt`

---

## ✨ Features

| Module | Details |

|---|---|

| 🌐 **Websites** | Create/delete Nginx sites, multi-PHP versions, vhost automatically |

| 🗄 **Database** | MySQL 8.4 LTS - 9, general & site-specific phpMyAdmin |

| 📁 **File Manager** | Upload, edit, chmod, multi-select delete, archive |

| 🔒 **SSL** | Certbot auto-renew, Let's Encrypt 1-click |

| 🛡 **Fail2ban** | Protect SSH + panel from brute-force attacks |

| ⚙️ **Services** | Manage nginx, php-fpm, mysqld, redis |

| 🎫 **License** | Free full features · Pro 50k for direct support |

| 🔗 **Sharing** | Self-host installer for others |

---

## 💎 License

**This panel is 100% free — full features, unlimited lifetime use.**

| | 🆓 Free | ⭐ Pro ($3 lifetime) |

|---|:---:|:---:|

| All features | ✅ | ✅ |

| Lifetime use | ✅ | ✅ |

| Community support (GitHub Issues) | ✅ | ✅ |

| Direct Telegram/Zalo support | ❌ | ✅ |

| Priority Bug Fixes | ❌ | ✅ |

Soon Updates | ❌ | ✅ |

> A Pro License is simply a way to **support the developers** — it doesn't lock any panel features.

📨 Purchase via: [Telegram](https://netihot.com/in4/) · [Zalo](https://netihot.com/in4/)

---

## 📋 System Requirements

- **OS:** All Redhat distributions or best of all, AlmaLinux 9/10, Rocky Linux 9, RHEL 9 (CentOS Stream 9 also runs)

- **CPU:** 1 core or more
- **RAM:** ≥ 1 GB (2 GB recommended)

- **Disk:** ≥ 5 GB

- **Permissions:** root (sudo)

- **Network:** Open ports 8765 (panel), 80, 443 (web) Firewall

---
## 🛠 Build from source

```bash
git clone https://github.com/trongthangno9-nitpanel/nitpanel.git
cd nitpanel
cargo build --release
sudo install -m 755 target/release/nitpanel /opt/nitpanel/nitpanel
```

---
## 🚀 New Release (for maintainers)

```bash
git tag v2.4.1
git push origin v2.4.1
```

GitHub Actions will automatically build the binary and publish the release. Users installing with one command will automatically get the latest version.

---

## 🐛 Report Bugs

- 🐞 Free: [GitHub Issues](https://github.com/trongthangno9-nitpanel/nitpanel/issues)

- 🎫 Pro license: [Telegram](https://netihot.com/in4/) / [Zalo](https://netihot.com/in4/)

---

## 📜 License (Source Code)

MIT — you are allowed to fork, modify, and use it for personal or commercial projects.
