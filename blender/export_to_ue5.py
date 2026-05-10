"""
Pufferspeicher -> Unreal Engine 5 Export
========================================

Wendet alle Modifier an, erzwingt echte Smoothing Groups durch einen
Edge-Split-Pass und exportiert eine FBX-Datei, die UE5 sauber importiert
(keine "No smoothing group information"-Warnung mehr).

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
import math
import os

# >>> Pfad anpassen <<<
EXPORT_PATH = "/tmp/pufferspeicher_800L.fbx"

# Welche Objekt-Praefixe gehoeren zum Modell?
INCLUDE_PREFIXES = (
    "Pufferspeicher_", "Stutzen_", "Thermohuelse_", "Typenschild",
)

# Winkel ab dem eine Kante als "hart" gilt (Edge Split)
SHARP_ANGLE_DEG = 30.0


def collect_model_objects():
    return [o for o in bpy.data.objects
            if o.type == "MESH" and o.name.startswith(INCLUDE_PREFIXES)]


def apply_all_modifiers(obj):
    """Wendet alle vorhandenen Modifier am Objekt an."""
    bpy.context.view_layer.objects.active = obj
    for mod in list(obj.modifiers):
        try:
            bpy.ops.object.modifier_apply(modifier=mod.name)
        except RuntimeError as exc:
            print(f"  ! konnte Modifier {mod.name} nicht anwenden: {exc}")
            try:
                obj.modifiers.remove(mod)
            except Exception:
                pass


def force_smoothing_groups(obj, sharp_angle_deg=SHARP_ANGLE_DEG):
    """Erzwingt UE5-kompatible Smoothing Groups.

    1. Edge-Split-Modifier: spaltet harte Kanten ab einem Winkel physisch ab.
       Dadurch entstehen geometrische Inseln, die im FBX als separate
       Smoothing Groups landen.
    2. Alle Polygone werden auf use_smooth=True gesetzt, alle Edges
       use_edge_sharp=False - das ist die saubere Basis fuer den
       Smoothing-Layer im FBX.
    """
    bpy.ops.object.select_all(action="DESELECT")
    obj.select_set(True)
    bpy.context.view_layer.objects.active = obj

    es = obj.modifiers.new("__EdgeSplit_Export", "EDGE_SPLIT")
    es.split_angle = math.radians(sharp_angle_deg)
    es.use_edge_angle = True
    es.use_edge_sharp = True
    try:
        bpy.ops.object.modifier_apply(modifier=es.name)
    except RuntimeError as exc:
        print(f"  ! Edge-Split fehlgeschlagen ({obj.name}): {exc}")
        if es.name in obj.modifiers:
            obj.modifiers.remove(es)

    me = obj.data
    for poly in me.polygons:
        poly.use_smooth = True
    for edge in me.edges:
        edge.use_edge_sharp = False
    me.update()


def prepare_for_export():
    objs = collect_model_objects()
    print(f"Bereite {len(objs)} Objekte fuer Export vor ...")
    bpy.ops.object.select_all(action="DESELECT")
    for o in objs:
        apply_all_modifiers(o)
        force_smoothing_groups(o)
    # zum Schluss alles selektieren fuer den Export
    bpy.ops.object.select_all(action="DESELECT")
    for o in objs:
        o.select_set(True)
    if objs:
        bpy.context.view_layer.objects.active = objs[0]
    return objs


def export_fbx(path, objs):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    # WICHTIG fuer UE5:
    # - mesh_smooth_type='FACE' schreibt den Smoothing-Layer ins FBX.
    # - bake_space_transform=False, sonst kann der Smoothing-Layer
    #   in manchen Blender-4.x-Versionen verlorengehen.
    # - use_tspace=True liefert Tangenten fuer Normal Maps.
    bpy.ops.export_scene.fbx(
        filepath=path,
        use_selection=True,
        global_scale=1.0,
        apply_unit_scale=True,
        apply_scale_options="FBX_SCALE_NONE",
        bake_space_transform=False,
        object_types={"MESH"},
        use_mesh_modifiers=True,
        mesh_smooth_type="FACE",
        use_subsurf=False,
        use_mesh_edges=False,
        use_tspace=True,
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
