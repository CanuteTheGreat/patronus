# Patronus branding

`patronus-logo-official.png` (1024x1536) is the **official Patronus logo**, supplied by the owner on 2026-10-28.
Do not redraw or restyle it. Everything else in this directory is derived from it by crop, scale and a dark
rounded background tile only (no AI upscaling, no redrawing); regenerate with `branding/derive.py`.

| file | what | used by |
|---|---|---|
| `patronus-logo-official.png` | the original | source of truth, README header |
| `patronus-mark-{512,256,180,128,64}.png` | emblem (phoenix + gear + sword), no wordmark, dark rounded tile | web sidebar/top bar, apple-touch-icon (180), installer, boot menu |
| `patronus-mark-{48,32,16}.png`, `favicon.ico` | tight phoenix head/wing crop (the full emblem turns to mush below ~48 px) | favicon, tab icons |
| `patronus-wordmark.png` | the fiery `PATRONUS` text only | wide headers |
| `patronus-full-half.png` | the whole logo at 512x768 | login page, boot splash, installer welcome |

The web UI embeds the web-sized subset from `crates/patronus-web/static/brand/` (copies of these files).
The live ISO / installer / GRUB theme read `branding/` (see `gentoo/live-iso/`).
| `patronus-grub-splash.png` | 1024x768 GRUB background: the full logo scaled and centred under the menu (compose with the full logo only) | live-ISO boot menu |
