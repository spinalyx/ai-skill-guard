# Polisa bezbednosti za AI skilove

**Verzija 0.1 · 7. novembar 2026 · Agoga**

Ova polisa je za svakoga ko instalira skilove, pluginove ili MCP servere za AI agente (Claude Code, Claude Desktop, Cursor, Codex i slične). Pisana je za ljude koji nisu programeri, ali odlučuju šta će raditi na njihovom računaru.

## 1. Šta je skill, zapravo

Skill izgleda kao uputstvo: tekstualni fajl `SKILL.md` i par skripti. Ali agent to uputstvo **izvršava**, sa tvojim pravima. Može da čita tvoje fajlove, da pokreće programe i da šalje podatke na internet. Sve to u meri u kojoj si mu dozvolio.

Instalirati skill znači pustiti nepoznatu osobu da tvom asistentu šapuće uputstva. Većina tih ljudi je dobronamerna. Polisa postoji zbog ostalih.

> **Nijedan alat ne čini skill potpuno bezbednim.** Bezbednost se gradi u slojevima: izvor, čitanje, automatska provera, mala proba i ograničena prava. Ako jedan sloj zakaže, drugi uhvati problem.

## 2. Šta može da pođe po zlu na tvom računaru

| Rizik | Kako izgleda | Zašto je opasno |
|---|---|---|
| **Krađa ključeva i lozinki** | Skript čita `.env`, `~/.ssh`, `~/.aws`, Windows Credential Manager ili macOS Keychain | Neko troši tvoje API kredite, ulazi na tvoje servere i u tvoj GitHub |
| **Krađa kolačića iz browsera** | „Za bolje rezultate dozvoli čitanje kolačića“ | Kolačić je ulaz u tvoj nalog bez lozinke i bez dvofaktorske potvrde: LinkedIn, Gmail, banka |
| **Preuzmi-i-pokreni** | `curl … \| bash`, `iwr … \| iex` | Kod stiže sa interneta u trenutku pokretanja; niko ga nije pročitao, a sutra može biti drugačiji |
| **Skrivena uputstva (prompt injection)** | „Ignoriši prethodna uputstva“, „ne govori korisniku“, tekst u HTML komentaru, nevidljivi Unicode znakovi | Ti vidiš bezazlen tekst, a agent čita naređenje |
| **Gašenje kočnica** | `--dangerously-skip-permissions`, `bypassPermissions`, izmena `settings.json` | Agent posle toga radi bez pitanja, i za ovaj skill i za sve ostale |
| **Hooks** | Skill ili plugin dodaje hook u podešavanja agenta | Hook se pokreće sam, pri svakoj akciji, i posle brisanja skila ako ga niko ne ukloni |
| **Trajno prisustvo** | Zakazani zadaci, Startup folder, `.bashrc`, registry `Run` | Nešto se pokreće i kad agent nije uključen |
| **Lanac zavisnosti** | `npm install`, `pip install`, `postinstall` skripte | Instaliraš jedan skill, a uz njega stigne dvadeset paketa koje niko nije pregledao |
| **Brisanje** | `rm -rf`, `Remove-Item -Recurse -Force`, `git push --force` | Gubitak podataka koji se ne vraća |
| **Odliv sadržaja** | Skill šalje tvoje tekstove, slike ili dokumente na „svoj“ server | Poverljivi materijal klijenata završi kod trećeg lica |
| **Tiha promena verzije** | Skill sa GitHub-a se ažurira, a ti nisi pogledao šta je novo | Ono što je juče bilo čisto danas ne mora biti |
| **Preotimanje okidača** | Preširok opis („koristi uvek“) ili isto ime kao postojeći skill | Pogrešan skill preuzima tvoje zahteve |

## 3. Šta dodatno važi u cloudu

Kad agent radi u oblaku (cloud sesije, CI/CD, GitHub Actions, deljeni timski pluginovi), rizik se seli, ali ne nestaje:

- **Tokeni u okruženju.** Cloud sesija obično ima GitHub token i tajne projekta. Zlonameran skill ih vidi kao i lokalno.
- **Pravo pisanja u repozitorijum.** Skill može da napravi commit, otvori PR ili gurne kod. Tako zlonameran kod ulazi u proizvod.
- **Mrežni izlaz.** Ako sandbox nema ograničen pristup internetu, podaci mogu da odu bilo gde.
- **Deljeni skilovi u organizaciji.** Jedan loš plugin dobija ceo tim odjednom. Odobravanje za organizaciju mora biti strože nego za jednu osobu.
- **Logovi.** Tajne koje skript ispiše završavaju u logovima koje vidi više ljudi.

Pravilo za cloud: **najmanje tajni, najmanje prava, ograničena mreža.** Daj cloud okruženju samo ključ koji mu treba, sa najkraćim rokom i najužim ovlašćenjem.

## 4. Pravila

1. **Izvor.** Instaliraj iz zvaničnih izvora ili od autora koji ima istoriju, licencu i aktivan repozitorijum. Skill iz poruke, Discord-a ili nepoznatog sajta automatski je visok rizik.
2. **Pročitaj sve.** Ne samo `SKILL.md`, nego i svaki fajl u `scripts/`, `references/` i `hooks/`. Ako ne umeš da čitaš kod, neka ga pročita neko ko ume, ili agent u posebnoj sesiji koja **nema** taj skill.
3. **Skeniraj.** Pokreni `skill-guard` pre instalacije. Svaki nalaz `critical` ili `high` mora imati objašnjenje pre nego što se nastavi.
4. **Zaključaj verziju.** Zapiši tačan commit ili verziju koju si pregledao. Ne instaliraj sa „latest“.
5. **Ažuriranje je nova instalacija.** Pre ažuriranja pogledaj šta se promenilo i ponovo skeniraj.
6. **Nikad ne isključuj dozvole.** Bez `--dangerously-skip-permissions` i bez „allow all“. Agent treba da pita.
7. **Kolačiće i lozinke ne daješ skilu.** Ako skill traži kolačiće iz browsera, odgovor je NE. Ključeve unosiš sam, u okruženje, a ne u chat.
8. **Prvo mala proba.** Novi skill prvo probaj na test folderu, bez tajni. Ako radi nešto veliko, probaj ga u posebnom korisničkom nalogu, virtuelnoj mašini ili kontejneru.
9. **Vodi inventar.** Spisak instaliranog: šta je, odakle, koja verzija, ko je odobrio i kad. Šta niko ne koristi, ukloni.
10. **Jedna odluka, jedan čovek.** Za svaki skill zna se ko je rekao „da“.

## 5. Kontrolna lista pre instalacije

- [ ] Znam ko je autor i odakle skill dolazi
- [ ] Licenca postoji i dozvoljava korišćenje
- [ ] Pročitan je svaki fajl, ne samo opis
- [ ] `skill-guard` nema nerešenih `critical` ili `high` nalaza
- [ ] Znam na koje adrese na internetu skill šalje podatke i zašto
- [ ] Skill ne traži kolačiće, lozinke ni isključivanje dozvola
- [ ] Ne dodaje hooks, MCP servere ni zakazane zadatke bez mog znanja
- [ ] Verzija je zapisana
- [ ] Probao sam ga prvo na malom, bez tajni
- [ ] Upisan je u inventar

## 6. Ako posumnjaš da je nešto loše instalirano

1. Prekini sesiju agenta i isključi mrežu ako se nešto dešava „samo od sebe“.
2. Ukloni skill i proveri da li je ostavio hooks (`settings.json`), MCP servere, zakazane zadatke i stavke koje se pokreću pri startu sistema.
3. **Promeni ključeve i lozinke** koje je mogao da vidi: API ključeve, GitHub tokene, i lozinke naloga čiji su kolačići bili u browseru (odjavi se sa svih uređaja).
4. Proveri potrošnju kod AI provajdera i nedavne commitove u repozitorijumima.
5. Zapiši šta se desilo, da se ne ponovi.

## 7. Automatska provera: skill-guard

`skill-guard` je mala Python skripta bez zavisnosti. Čita skill i traži poznate opasne obrasce. **Ne pokreće ništa od onoga što skenira.**

```bash
python skill_guard.py putanja/do/skila
```

Proverava: preuzmi-i-pokreni komande, skriveni i kodirani kod, sumnjive adrese za prijem ukradenih podataka, čitanje ključeva, lozinki i kolačića, kripto novčanike, trajno prisustvo, izmene podešavanja agenta (hooks, MCP, dozvole), skrivena uputstva i nevidljive Unicode znakove, opasno brisanje, podizanje privilegija, instalacione hookove paketa, izvršne fajlove, simboličke linkove i ZIP arhive koje pišu van foldera. Na kraju daje spisak svih adresa na internetu koje se pominju.

Šta **ne** može: da razume nameru, da uhvati potpuno nov trik, da pregleda pakete koje skill tek treba da preuzme. Zato je ona sloj 3 od 5, a ne zamena za čitanje.

Čist rezultat znači „nema poznatih crvenih zastavica“. Ne znači „bezbedno“.
