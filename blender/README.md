# Blender-Modelle

## `pufferspeicher.py`

Erzeugt prozedural einen fotorealistischen Heizungs-Pufferspeicher
(800 L, Ø 790 × 1810 mm) inklusive Isoliermantel, Deckel, seitlichen
Anschlussstutzen, Tauchhülsen und Typenschild.

### Verwendung

1. Blender ≥ 3.6 öffnen (getestet mit 4.x).
2. Tab **Scripting** → **Open** → `pufferspeicher.py` auswählen.
3. **Run Script** klicken.
4. `F12` für ein Cycles-Render (1600 × 2000 px, 256 Samples + Denoising).

### Anpassen

Im Kopf der Datei stehen die wichtigsten Parameter:

| Variable          | Bedeutung                                  |
|-------------------|--------------------------------------------|
| `TANK_DIAMETER`   | Außendurchmesser inkl. Isolierung (m)      |
| `TANK_HEIGHT`     | Gesamthöhe inkl. Deckel (m)                |
| `MANTLE_COLOR`    | Farbe des Skai-Mantels (RGBA)              |
| `PORTS`           | Liste der Anschlussstutzen (Höhe, Winkel…) |
| `THERMOWELLS`     | Liste der Thermometer-Tauchhülsen          |

Die Beleuchtung ist auf Studio-HDRI (Nishita-Sky) + Key/Fill-Area-Light
ausgelegt, die Kamera steht in 70-mm-Brennweite mit f/5.6 Tiefenschärfe.
