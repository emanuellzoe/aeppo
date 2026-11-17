# aeppo

`aeppo` adalah scanner statis lokal untuk menandai beberapa pola berisiko dan kredensial yang mungkin tertanam di source Python. Scanner tidak menjalankan kode yang dipindai.

## Status proyek

Prototipe awal. Saat ini hanya memindai file `.py` dan memiliki sejumlah kecil rules berbasis pola. Hasil bukan bukti bahwa kode berbahaya atau kredensial valid; false positive dan false negative mungkin terjadi.

## Persyaratan

- Python 3.9 atau lebih baru
- Tidak ada dependency eksternal

## Jalankan

Dari root repository:

```bash
python3 -m aeppo.cli scan PATH
```

Contoh:

```bash
python3 -m aeppo.cli scan ./some-repository
python3 -m aeppo.cli scan ./some-repository --format json
```

Mode teks menampilkan path, nomor baris, ID rule, dan alasan. Mode JSON menghasilkan array temuan dengan `path`, `line`, `rule_id`, dan `message`.

Exit status:

- `0`: scan sukses tanpa temuan
- `1`: scan sukses dengan temuan
- `2`: target tidak dapat dipindai / argumen tidak valid

## Rules saat ini

| ID | Deteksi | Catatan |
|---|---|---|
| `PY001` | Pemanggilan pola `os.system(` | Heuristik statis; konteks pemakaian perlu ditinjau |
| `SEC001` | Pola AWS access key ID berawalan `AKIA` | Tidak memvalidasi key atau status aktif |
| `SEC002` | Pola token GitHub berawalan `ghp_`, `gho_`, `ghu_`, `ghs_`, atau `ghr_` | Tidak memvalidasi token |
| `SEC003` | Header PEM private key umum | Mendeteksi header, bukan memastikan seluruh key valid |

Direktori tersembunyi, `.git`, `.hg`, `.svn`, `.venv`, `venv`, `__pycache__`, dan `node_modules` dilewati saat traversal folder.

## Batasan keamanan

- Pemindaian bersifat statis dan terbatas pada Python; kode target tidak dieksekusi.
- Rules regex sederhana dapat melewatkan variasi obfuscation atau menghasilkan false positive.
- Jangan menempelkan temuan berisi secret ke issue publik. Jika secret sungguhan terdeteksi, anggap terekspos dan cabut/rotasi melalui penyedia terkait.
- Jangan menganggap sandbox sebagai jaminan mutlak bila kelak melakukan analisis dinamis.

## Tes

```bash
python3 -m unittest discover -s tests -v
```

Kontribusi rules baru sebaiknya menyertakan tes positif dan negatif dengan nilai dummy, bukan kredensial sungguhan.
