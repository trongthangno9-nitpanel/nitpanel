# 📘 Hướng dẫn deploy NITPANEL lên GitHub

Tài liệu này dành cho **bạn** (maintainer) — chỉ làm 1 lần là xong.

---

## 🎯 Mục tiêu

Sau khi làm xong, bất kỳ ai cũng có thể cài panel của bạn bằng 1 dòng lệnh:

```bash
curl -fsSL https://raw.githubusercontent.com/trongthangno9-nitpanel/nitpanel/main/one-line-install.sh | sudo bash
```

---

## 📋 Bước 1: Tạo repo trên GitHub

1. Vào [github.com/new](https://github.com/new)
2. Repository name: **`nitpanel`** (đúng tên này, đừng đặt khác)
3. Visibility: **Public**
4. **KHÔNG** tick "Add README" hay "Add .gitignore" (đã có sẵn trong source rồi)
5. Click **Create repository**

---

## 📋 Bước 2: Push source lên repo

Trên máy của bạn (có git cài sẵn):

```bash
# Giải nén source
tar -xzf nitpanel-v2_4_1_updated.tar.gz
cd nitpanel

# Init git
git init -b main
git add .
git commit -m "Initial release v2.4.1"

# Kết nối với repo GitHub
git remote add origin https://github.com/trongthangno9-nitpanel/nitpanel.git

# Push lên
git push -u origin main
```

> Nếu git hỏi mật khẩu → dùng **Personal Access Token** thay cho password.
> Tạo token tại: [github.com/settings/tokens](https://github.com/settings/tokens) → Generate new token (classic) → tick `repo` scope.

---

## 📋 Bước 3: Tạo Release đầu tiên (build binary)

Sau khi push xong, tag 1 phiên bản để GitHub Actions tự build binary:

```bash
git tag v2.4.1
git push origin v2.4.1
```

Vào **tab Actions** trên repo GitHub → đợi workflow chạy xong (~5-7 phút).

Khi xong, vào **tab Releases** sẽ thấy `v2.4.1` với file `nitpanel-almalinux.tar.gz` đính kèm.

---

## 📋 Bước 4: Test cài thử trên VPS mới

Thuê 1 VPS AlmaLinux 9 rẻ tiền (LightNode, Vultr, DigitalOcean...) → chạy:

```bash
curl -fsSL https://raw.githubusercontent.com/trongthangno9-nitpanel/nitpanel/main/one-line-install.sh | sudo bash
```

Nếu cài xong trong ~30 giây (không build từ source) → ✅ Release đã hoạt động đúng.
Nếu nó build từ source ~5-10 phút → kiểm tra lại GitHub Actions có lỗi không.

---

## 🔄 Workflow cập nhật phiên bản mới

Mỗi khi có bản cập nhật:

```bash
# 1. Sửa code, test ổn
vim src/main.rs
cargo build --release  # Test local

# 2. Update version
sed -i 's/v2_4_0/v2_4_1/g' frontend/index.html  # nếu cần
sed -i 's/version = "2.4.0"/version = "2.4.1"/' Cargo.toml

# 3. Commit & tag
git add .
git commit -m "Release v2.4.2: fix abc, thêm xyz"
git tag v2.4.2
git push origin main --tags
```

GitHub Actions sẽ tự build và publish Release. Người dùng chỉ cần chạy lại lệnh cài 1 dòng → có bản mới.

---

## 🎫 Quản lý license Pro

Panel này dùng **license server tập trung** (project riêng, **PRIVATE**, đặt trên VPS của bạn).

### Architecture

```
┌─────────────────┐                    ┌──────────────────┐
│ Panel của khách │  ── activate ──>   │ License Server   │
│ (cài qua GitHub)│  <── verify ──     │ license.your.com │
│   PUBLIC code   │                    │   PRIVATE code   │
└─────────────────┘                    └──────────────────┘
```

- Code panel public → ai đọc cũng được, **không sinh được key** vì thuật toán + secret nằm ở server.
- License server private → bạn host trên VPS riêng, có domain HTTPS.

### Setup

1. Tải project `license-server` (file riêng `nitpanel-license-server.tar.gz`)
2. Up lên VPS riêng (KHÔNG cùng repo public!)
3. Chạy `sudo bash setup.sh`
4. Trỏ domain `license.yourdomain.com` về VPS đó, cài SSL
5. Sửa trong `src/main.rs` của panel:
   ```rust
   const LICENSE_SERVER_URL: &str = "https://license.yourdomain.com";
   ```
6. Commit + push panel lên GitHub

### Cấp key hằng ngày

1. Khách thanh toán 50k qua Telegram/Zalo
2. Bạn vào `https://license.yourdomain.com/admin`
3. Điền thông tin khách → bấm **Tạo key mới**
4. Copy key dạng `NIT-XXXX-XXXX-XXXX-XXXX` gửi khách
5. Khách dán vào panel của họ → activate

### Bảo mật

- Mỗi key **giới hạn 3 server** (chống share tràn lan)
- **Revoke** được bất cứ lúc nào (chargeback, vi phạm...)
- Tracking đầy đủ: server_id, IP, version, last_check
- Secret HMAC chỉ nằm trên VPS bạn → ai có source panel cũng không tạo được key

---

## 🆘 Troubleshooting

### Workflow Actions báo lỗi "permission denied"
→ Vào **Settings** repo → **Actions** → **General** → **Workflow permissions** → tick **Read and write permissions** → Save.

### `git push` báo "remote rejected"
→ Repo đã có sẵn file (do bạn lỡ tick README/gitignore lúc tạo) → chạy:
```bash
git pull origin main --allow-unrelated-histories
git push -u origin main
```

### Người dùng cài báo "404 Not Found"
→ Repo chưa Public, hoặc URL sai. Vào **Settings** → **General** → cuộn xuống **Danger Zone** → **Change visibility** → Public.
