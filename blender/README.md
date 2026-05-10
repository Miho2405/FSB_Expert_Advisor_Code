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

---

## Export nach Unreal Engine 5

### 1. FBX exportieren (`export_to_ue5.py`)

1. Erst `pufferspeicher.py` in Blender laufen lassen.
2. `export_to_ue5.py` öffnen, `EXPORT_PATH` oben auf einen lokalen Pfad
   setzen (z. B. `C:/Temp/pufferspeicher_800L.fbx`).
3. `Run Script`. Das Skript wendet alle Modifier (Bevel, …) an und
   exportiert eine UE5-kompatible FBX (Y-up, Smoothing-Groups, Tangenten).

### 2. In UE5 importieren

1. Content Browser → Rechtsklick → **Import to /Game/...** → FBX wählen.
2. Im Import-Dialog folgende Einstellungen:

   | Option                       | Wert            |
   |------------------------------|-----------------|
   | Import Uniform Scale         | `100`           |
   | Convert Scene                | aus             |
   | Force Front XAxis            | aus             |
   | Combine Meshes               | aus             |
   | Auto Generate Collision      | ein             |
   | Generate Lightmap UVs        | ein             |
   | Import Materials             | ein             |
   | Material Search Location     | `Local`         |

3. Drag & Drop in das Level. Maße sollten ~79 cm × 181 cm passen.

### 3. Materialien (in UE5 nachbauen)

Die prozedurale Skai-Bump-Textur aus Blender wird **nicht** mit
exportiert. In UE5 brauchst du fünf einfache PBR-Materialien:

| Slot          | Base Color (sRGB) | Metallic | Roughness | Hinweise                               |
|---------------|-------------------|----------|-----------|----------------------------------------|
| Skai-Mantel   | #0D1A2E           | 0.0      | 0.55      | Noise → Bump für Skai-Struktur         |
| Deckel        | #0A0A0D           | 0.0      | 0.60      | wie oben, Scale kleiner                |
| Sockel        | #050505           | 0.0      | 0.70      |                                        |
| Edelstahl     | #C7C7CC           | 1.0      | 0.28      | leichte Anisotropy für Bürstenoptik    |
| Typenschild   | #D9D9E0           | 0.6      | 0.35      | optional Logo-Textur                   |

**Skai-Bump in UE5 schnell nachbauen:**
`Texture Coordinate` → `Multiply (×120)` → `Noise` (Quality: Medium,
Levels: 4) → `BumpOffset` oder direkt in `Normal` Input. Dann an
`Normal` des Material-Outputs hängen.

### 4. Alternative: Bake & glTF

Wer die exakte Blender-Optik will:

1. UV-Unwrap (Smart UV Project) auf den Mantel.
2. `Render Properties → Bake → Bake Type: Normal`, ein neues Image
   `Mantel_Normal` zuweisen, **Bake**.
3. glTF-Export (`File → Export → glTF 2.0`) statt FBX – der
   glTF-Importer in UE5 übernimmt Base Color + Normal + Metallic/Rough
   automatisch.
