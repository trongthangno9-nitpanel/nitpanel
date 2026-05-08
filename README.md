# 🚀 NITPANEL

Panel quản lý web server cho **AlmaLinux / Rocky Linux / RHEL 9+** — Nginx, MySQL, PHP-FPM (7.4 → 8.4), Certbot SSL, Fail2ban, phpMyAdmin, File Manager.

Viết bằng **Rust + Actix-web 4** → nhẹ, nhanh, 1 binary duy nhất.

---

## ⚡ Cài đặt 1 dòng lệnh

```bash
curl -fsSL https://raw.githubusercontent.com/trongthangno9-nitpanel/nitpanel/main/one-line-install.sh | sudo bash
```

Hoàn tất trong ~30 giây nếu binary có sẵn, hoặc ~5-10 phút nếu phải build từ source.

Sau khi cài xong:
- 🌐 Truy cập panel: `http://<IP-VPS>:8765`
- 🔑 Mật khẩu: lưu tại `/etc/nitpanel/credentials.txt`

---

## ✨ Tính năng

| Module | Chi tiết |
|---|---|
| 🌐 **Websites** | Tạo/xóa site Nginx, multi-PHP version, vhost tự động |
| 🗄 **Database** | MySQL 9, phpMyAdmin chung & theo site |
| 📁 **File Manager** | Upload, edit, chmod, multi-select delete, archive |
| 🔒 **SSL** | Certbot auto-renew, Let's Encrypt 1-click |
| 🛡 **Fail2ban** | Bảo vệ SSH + panel khỏi brute-force |
| ⚙️ **Services** | Quản lý nginx, php-fpm, mysqld, redis |
| 🎫 **License** | Free đầy đủ tính năng · Pro 50k để hỗ trợ trực tiếp |
| 🔗 **Chia sẻ** | Tự host installer cho người khác |

---

## 💎 License

**Panel này 100% miễn phí — đầy đủ tính năng, dùng vĩnh viễn không giới hạn.**

| | 🆓 Free | ⭐ Pro (50.000₫ vĩnh viễn) |
|---|:---:|:---:|
| Toàn bộ tính năng | ✅ | ✅ |
| Dùng vĩnh viễn | ✅ | ✅ |
| Hỗ trợ cộng đồng (GitHub Issues) | ✅ | ✅ |
| Hỗ trợ trực tiếp Telegram/Zalo | ❌ | ✅ |
| Fix bug ưu tiên | ❌ | ✅ |
| Cập nhật sớm | ❌ | ✅ |

> Pro License chỉ là cách **ủng hộ dev** — không khoá tính năng nào của panel.

📨 Mua qua: [Telegram](https://t.me/netihot) · [Zalo](https://zalo.me/netihot)

---

## 📋 Yêu cầu hệ thống

- **OS:** AlmaLinux 9/10, Rocky Linux 9, RHEL 9 (CentOS Stream 9 cũng chạy)
- **CPU:** 1 core trở lên
- **RAM:** ≥ 1 GB (khuyên 2 GB)
- **Disk:** ≥ 5 GB
- **Quyền:** root (sudo)
- **Mạng:** mở port 8765 (panel), 80, 443 (web)

---

## 🛠 Build từ source

```bash
git clone https://github.com/trongthangno9-nitpanel/nitpanel.git
cd nitpanel
cargo build --release
sudo install -m 755 target/release/nitpanel /opt/nitpanel/nitpanel
```

---

## 🚀 Release mới (cho maintainer)

```bash
git tag v2.4.1
git push origin v2.4.1
```

GitHub Actions sẽ tự build binary và publish Release. Người dùng cài bằng 1 lệnh sẽ tự động lấy bản mới nhất.

---

## 🐛 Báo lỗi

- 🐞 Free: [GitHub Issues](https://github.com/trongthangno9-nitpanel/nitpanel/issues)
- 🎫 Pro license: [Telegram](https://t.me/netihot) / [Zalo](https://zalo.me/netihot)

---

## 📜 License (mã nguồn)

MIT — bạn được fork, sửa, dùng cho dự án cá nhân hoặc thương mại.
