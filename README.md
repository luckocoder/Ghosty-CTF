# Ghosty CTF

Yon aplikasyon Flask ki fèt pou yon CTF edikatif pou debutan. Aplikasyon an gen vilnerabilite espre epi li gen senk defi sou rekonesans, piki SQL, IDOR, piki kòmand, ak telechajman fichye ki pa an sekirite. Pa deplwaye aplikasyon sa a sou entènèt piblik ni nan yon anviwònman pwodiksyon.

## Kijan pou lanse aplikasyon an ak Docker

Bati imaj la epi lanse kontenè a:

```sh
docker build -t ghosty-ctf .
docker run --rm -p 8080:8080 ghosty-ctf
```

Louvri <http://localhost:8080>. Nan GitHub Codespaces, mete pò **8080** sou transmisyon epi ouvri adrès yo ba ou a.

Ou ka ranplase nenpòt drapo lè w lanse kontenè a, avèk varyab `FLAG1` rive `FLAG5`. Men yon egzanp:

```sh
docker run --rm -p 8080:8080 -e FLAG1="FLAG{your_custom_recon_flag}" ghosty-ctf
```

## Enfòmasyon sou defi yo

- **Defi 1 — Rekonesans:** `/robots.txt` bay enfòmasyon sou paj `/dev-notes.html` ki pa gen lyen nan meni an.
- **Defi 2 — Piki SQL:** Sou `/login`, mete `' OR '1'='1' -- ` kòm non itilizatè; nenpòt modpas ap mache.
- **Defi 3 — IDOR:** Konekte epi chanje nimewo ID ki nan `/profile/<id>`. Kont demonstrasyon yo se `alice` / `alice123` ak `bob` / `bob123`.
- **Defi 4 — Piki kòmand:** Sou `/ping`, eseye `127.0.0.1; cat flag4.txt`.
- **Defi 5 — Telechajman fichye ki pa an sekirite:** Voye yon fichye `.py` ki gen `print(open('flag5.txt').read())`, epi klike sou lyen **Lanse nan similatè a**. Aplikasyon an pa verifye ekstansyon ni kontni fichye a.

Pou sekirite, defi piki kòmand lan itilize yon ti similatè kòmand olye li lanse yon kokiy sistèm operasyon an. Li sipòte kòmand `ping` ak `cat flag4.txt` ki separe ak pwen-virgil. Similatè a trete fichye Python yo tou; li sipòte afiche tèks senp ak lekti fichye `flag5.txt` jan egzanp lan montre a. Li pa janm rele Python `eval` ni `exec`. Limit sa yo pèmèt patisipan yo jwenn drapo defi yo san yo pa egzekite kòmand oswa kòd abitrè nan kontenè a.
