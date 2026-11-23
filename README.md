# Kowa Kowo – Sistem Absensi Karyawan

Satu server, satu database (`data/db.json`). Panel Admin adalah satu-satunya sumber akun karyawan.

| Halaman | Alamat |
|---|---|
| Absensi karyawan | `/` |
| Panel admin | `/admin` |

## Menjalankan
Butuh Node.js 18 atau lebih baru. Tidak perlu `npm install`.

    ADMIN_PIN=PINRAHASIAMU node server.js

Windows (PowerShell):

    $env:ADMIN_PIN="PINRAHASIAMU"; node server.js

Buka http://localhost:3000 (karyawan) dan http://localhost:3000/admin (admin).

## Pengaturan (environment variable)
- `ADMIN_PIN` – PIN login admin. WAJIB diganti (bawaan 1234).
- `PORT` – port server (bawaan 3000).
- `DATA_DIR` – folder database (bawaan `./data`).
- `TZ_OFFSET` – selisih zona waktu dari UTC (bawaan 7 = WIB).

## Cara kerja
- Tambah karyawan di Panel Admin, lalu akun itu langsung bisa login.
- Ubah password di Panel Admin, lalu password lama langsung tidak berlaku.
- Hapus karyawan di Panel Admin, lalu nama dan password itu menghasilkan "Pengguna Tidak Ditemukan". Sesi yang sedang login ikut ditolak pada permintaan berikutnya.
- Setiap login dan setiap aksi karyawan dicek ke database. Tidak ada akun yang disimpan terpisah di browser.
- Password disimpan terenkripsi (AES-256-GCM) dengan kunci di `data/secret.key`. Admin tetap bisa melihatnya di daftar.
- Salah login 8 kali dalam 10 menit akan dikunci sementara.

## Memasang online (supaya bisa dibuka dari HP karyawan)
Pakai layanan hosting Node.js (Railway, Render, VPS, dll.):
1. Unggah folder ini.
2. Perintah start: `node server.js`
3. Atur `ADMIN_PIN`.
4. PENTING: pasang penyimpanan permanen (persistent disk/volume) dan arahkan `DATA_DIR` ke sana. Tanpa itu, data hilang saat server restart.
5. Pakai HTTPS (disediakan otomatis oleh layanan hosting).

## Backup
Salin folder `data/` (berisi `db.json` dan `secret.key`) secara berkala. Keduanya harus disimpan bersama.
