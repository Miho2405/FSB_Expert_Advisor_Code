"""
Pufferspeicher -> Unreal Engine 5 Export
========================================

Wendet alle Modifier an, fasst das Modell zu sinnvollen Gruppen
zusammen und exportiert eine FBX-Datei, die UE5 sauber importiert.

Voraussetzung: pufferspeicher.py wurde bereits ausgefuehrt
(Szene enthaelt die Objekte "Pufferspeicher_*", "Stutzen_*" usw.).

Verwendung in Blender:
    1. Erst pufferspeicher.py ausfuehren.
    2. Dann diese Datei oeffnen, EXPORT_PATH unten anpassen.
    3. Run Script.
    4. In UE5: Content Browser -> Import -> die FBX waehlen.

UE5-Importeinstellungen (siehe README):
    - Import Uniform Scale: 100 (Blender m -> UE cm)
    - Combine Meshes: aus (mehrere Materialslots)
    - Auto Generate Collision: ein
    - Generate Lightmap UVs: ein (fuer statische Beleuchtung)
"""

import bpy
import os

# >>> Pfad anpassen <<<
EXPORT_PATH = "/tmp/pufferspeicher_800L.fbx"

# Welche Objekt-Praefixe gehoeren zum Modell?
INCLUDE_PREFIXES = (
    "Pufferspeicher_", "Stutzen_", "Thermohuelse_", "Typenschild",
)


def collect_model_objects():
    return [o for o in bpy.data.objects
            if o.type == "MESH" and o.name.startswith(INCLUDE_PREFIXES)]


def apply_all_modifiers(obj):
    """Wendet alle Modifier am gegebenen Objekt an."""
    bpy.context.view_layer.objects.active = obj
    for mod in list(obj.modifiers):
        try:
            bpy.ops.object.modifier_apply(modifier=mod.name)
        except RuntimeError as exc:
            print(f"  ! konnte Modifier {mod.name} nicht anwenden: {exc}")


def prepare_for_export():
    objs = collect_model_objects()
    print(f"Bereite {len(objs)} Objekte fuer Export vor ...")
    bpy.ops.object.select_all(action="DESELECT")
    for o in objs:
        o.select_set(True)
        apply_all_modifiers(o)
    return objs


def export_fbx(path, objs):
    bpy.ops.object.select_all(action="DESELECT")
    for o in objs:
        o.select_set(True)
    bpy.context.view_layer.objects.active = objs[0]

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    # WICHTIG: mesh_smooth_type muss 'FACE' oder 'EDGE' sein, damit UE5
    # Smoothing Groups bekommt. 'OFF' fuehrt zur Warnung
    # "No smoothing group information was found in this FBX scene".
    # bake_space_transform=False lassen - in Kombination mit FACE-Smoothing
    # gehen in einigen Blender-Versionen sonst die Gruppen verloren.
    bpy.ops.export_scene.fbx(
        filepath=path,
        use_selection=True,
        global_scale=1.0,
        apply_unit_scale=True,
        apply_scale_options="FBX_SCALE_NONE",
        bake_space_transform=False,
        object_types={"MESH"},
        use_mesh_modifiers=True,
        mesh_smooth_type="FACE",     # <- Smoothing Groups fuer UE5
        use_subsurf=False,
        use_mesh_edges=False,
        use_tspace=True,             # Tangenten fuer Normal Maps
        use_triangles=False,
        use_custom_props=False,
        add_leaf_bones=False,
        path_mode="COPY",
        embed_textures=False,
        axis_forward="-Z",
        axis_up="Y",
    )
    print(f"FBX exportiert: {path}")


def main():
    objs = prepare_for_export()
    if not objs:
        print("Keine Pufferspeicher-Objekte gefunden. "
              "Erst pufferspeicher.py ausfuehren!")
        return
    export_fbx(EXPORT_PATH, objs)
    print("Fertig. In UE5 importieren - Anleitung siehe blender/README.md.")


if __name__ == "__main__":
    main()
