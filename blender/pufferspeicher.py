"""
Pufferspeicher 800 L - prozedurales Blender-Modell
==================================================

Erzeugt einen fotorealistischen Heizungs-Pufferspeicher (800 L,
Ø 790 mm x H 1810 mm) mit Isoliermantel, Deckel, seitlichen
Anschlussstutzen, Thermometertauchhuelse und Typenschild.

Verwendung in Blender (>= 3.6, getestet mit 4.x):
    1. Blender oeffnen, leere Szene anlegen.
    2. Tab "Scripting" -> "Open" -> diese Datei waehlen.
    3. "Run Script" druecken.
    4. F12 fuer Cycles-Render.

Einheiten: Meter. Render-Engine: Cycles, HDRI-Studiobeleuchtung.
"""

import bpy
import bmesh
import math
from mathutils import Vector

# ---------------------------------------------------------------------------
# Konfiguration (Masse in Metern)
# ---------------------------------------------------------------------------

TANK_DIAMETER       = 0.790     # Aussendurchmesser inkl. Isolierung
TANK_HEIGHT         = 1.810     # Gesamthoehe inkl. Deckel
INSULATION_TOP      = 0.090     # Dicke der Deckelisolierung
BASE_HEIGHT         = 0.040     # Hoehe Standfuss / Sockel
MANTLE_COLOR        = (0.05, 0.10, 0.18, 1.0)   # dunkelblauer Skai-Mantel
LID_COLOR           = (0.04, 0.04, 0.05, 1.0)   # anthrazit
SEAM_OFFSET_DEG     = 180                       # Position des Reissverschlusses

# Anschlussstutzen: (Hoehe ueber Boden in m, Winkel in Grad, Innen-Durchmesser, Laenge)
PORTS = [
    (1.700,   0,  0.040, 0.075),  # Vorlauf oben
    (1.520,  60,  0.040, 0.075),
    (1.520, 300,  0.040, 0.075),
    (1.150,   0,  0.040, 0.075),
    (1.150, 180,  0.040, 0.075),
    (0.780,  60,  0.040, 0.075),
    (0.780, 300,  0.040, 0.075),
    (0.380,   0,  0.040, 0.075),  # Ruecklauf unten
    (0.380, 180,  0.040, 0.075),
    (0.140,   0,  0.025, 0.075),  # Entleerung
]

# Tauchhuelsen fuer Thermometer (Hoehe, Winkel)
THERMOWELLS = [
    (1.450, 120, 0.018, 0.060),
    (1.000, 120, 0.018, 0.060),
    (0.550, 120, 0.018, 0.060),
]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def clear_scene():
    """Loescht alle Objekte und nicht referenzierten Daten."""
    bpy.ops.object.select_all(action="SELECT")
    bpy.ops.object.delete(use_global=False)
    for block in (bpy.data.meshes, bpy.data.materials,
                  bpy.data.textures, bpy.data.images):
        for item in list(block):
            if item.users == 0:
                block.remove(item)


def make_principled(name, base_color, roughness=0.5, metallic=0.0,
                    sheen=0.0, clearcoat=0.0, normal_strength=0.0):
    """Erzeugt ein Material mit Principled BSDF."""
    mat = bpy.data.materials.new(name)
    mat.use_nodes = True
    nt = mat.node_tree
    bsdf = nt.nodes.get("Principled BSDF")
    bsdf.inputs["Base Color"].default_value = base_color
    bsdf.inputs["Roughness"].default_value = roughness
    bsdf.inputs["Metallic"].default_value = metallic
    # Sheen / Clearcoat heissen je nach Blender-Version unterschiedlich
    for key, value in (("Sheen Weight", sheen), ("Sheen", sheen),
                       ("Coat Weight", clearcoat), ("Clearcoat", clearcoat)):
        if key in bsdf.inputs:
            bsdf.inputs[key].default_value = value
    return mat


def add_skai_texture(mat, scale=80.0, bump_strength=0.6):
    """Fuegt prozedurale Noise-Bump-Textur fuer Skai-Optik hinzu."""
    nt = mat.node_tree
    bsdf = nt.nodes.get("Principled BSDF")
    out = nt.nodes.get("Material Output")

    tex_coord = nt.nodes.new("ShaderNodeTexCoord")
    mapping   = nt.nodes.new("ShaderNodeMapping")
    noise     = nt.nodes.new("ShaderNodeTexNoise")
    bump      = nt.nodes.new("ShaderNodeBump")

    mapping.inputs["Scale"].default_value = (scale, scale, scale)
    noise.inputs["Detail"].default_value = 6.0
    noise.inputs["Roughness"].default_value = 0.55
    bump.inputs["Strength"].default_value = bump_strength
    bump.inputs["Distance"].default_value = 0.002

    nt.links.new(tex_coord.outputs["Generated"], mapping.inputs["Vector"])
    nt.links.new(mapping.outputs["Vector"],      noise.inputs["Vector"])
    nt.links.new(noise.outputs["Fac"],           bump.inputs["Height"])
    nt.links.new(bump.outputs["Normal"],         bsdf.inputs["Normal"])

    # Layout
    for n, x in ((tex_coord, -900), (mapping, -700), (noise, -450), (bump, -220)):
        n.location = (x, -200)


def assign_material(obj, mat):
    if obj.data.materials:
        obj.data.materials[0] = mat
    else:
        obj.data.materials.append(mat)


def shade_smooth(obj, angle_deg=30):
    """Shade Smooth - kompatibel mit Blender 3.x und 4.x.

    In Blender 4.1+ wurde mesh.use_auto_smooth entfernt; die Auto-Smooth
    Funktion liegt jetzt im Operator 'shade_smooth_by_angle'. Wir versuchen
    diesen, fallen sonst auf die Legacy-API zurueck.
    """
    bpy.ops.object.select_all(action="DESELECT")
    obj.select_set(True)
    bpy.context.view_layer.objects.active = obj
    if hasattr(bpy.ops.object, "shade_smooth_by_angle"):
        try:
            bpy.ops.object.shade_smooth_by_angle(angle=math.radians(angle_deg))
            return
        except Exception:
            pass
    bpy.ops.object.shade_smooth()
    if hasattr(obj.data, "use_auto_smooth"):
        try:
            obj.data.use_auto_smooth = True
            if hasattr(obj.data, "auto_smooth_angle"):
                obj.data.auto_smooth_angle = math.radians(angle_deg)
        except AttributeError:
            pass


# ---------------------------------------------------------------------------
# Geometrie
# ---------------------------------------------------------------------------

def build_body(mat_mantle, mat_lid, mat_base):
    """Mantel (geschlossen), gewoelbter Deckel und Sockel."""
    radius = TANK_DIAMETER / 2
    body_depth = TANK_HEIGHT - INSULATION_TOP - BASE_HEIGHT
    body_z = BASE_HEIGHT + body_depth / 2

    # Hauptmantel - geschlossener Zylinder (NGON-Caps), damit nichts "offen" ist
    bpy.ops.mesh.primitive_cylinder_add(
        vertices=128,
        radius=radius,
        depth=body_depth,
        location=(0, 0, body_z),
        end_fill_type="NGON",
    )
    mantle = bpy.context.active_object
    mantle.name = "Pufferspeicher_Mantel"
    bevel = mantle.modifiers.new("Bevel", "BEVEL")
    bevel.width = 0.004
    bevel.segments = 3
    bevel.limit_method = "ANGLE"
    bevel.angle_limit = math.radians(40)
    shade_smooth(mantle)
    assign_material(mantle, mat_mantle)

    # Gewoelbter Deckel: obere Haelfte einer UV-Sphere, gestaucht
    bpy.ops.mesh.primitive_uv_sphere_add(
        segments=128, ring_count=64, radius=radius,
        location=(0, 0, TANK_HEIGHT - INSULATION_TOP),
    )
    lid = bpy.context.active_object
    lid.name = "Pufferspeicher_Deckel"
    # untere Haelfte wegschneiden
    me = lid.data
    bm = bmesh.new()
    bm.from_mesh(me)
    bmesh.ops.bisect_plane(
        bm, geom=bm.verts[:] + bm.edges[:] + bm.faces[:],
        plane_co=(0, 0, TANK_HEIGHT - INSULATION_TOP),
        plane_no=(0, 0, -1),
        clear_inner=True,
    )
    # Boden-Ngon schliessen
    open_edges = [e for e in bm.edges if e.is_boundary]
    if open_edges:
        bmesh.ops.holes_fill(bm, edges=open_edges, sides=0)
    bm.to_mesh(me)
    bm.free()
    # flach druecken: Hoehe = INSULATION_TOP statt radius
    lid.scale.z = INSULATION_TOP / radius
    bpy.ops.object.transform_apply(location=False, rotation=False, scale=True)
    shade_smooth(lid)
    assign_material(lid, mat_lid)

    # Sockel
    bpy.ops.mesh.primitive_cylinder_add(
        vertices=64,
        radius=radius * 0.96,
        depth=BASE_HEIGHT,
        location=(0, 0, BASE_HEIGHT / 2),
        end_fill_type="NGON",
    )
    base = bpy.context.active_object
    base.name = "Pufferspeicher_Sockel"
    bevel = base.modifiers.new("Bevel", "BEVEL")
    bevel.width = 0.006
    bevel.segments = 4
    shade_smooth(base)
    assign_material(base, mat_base)

    return mantle, lid, base


def build_seam(mat_seam):
    """Vertikaler Reissverschluss / Naht am Mantel."""
    radius = TANK_DIAMETER / 2 + 0.003
    angle = math.radians(SEAM_OFFSET_DEG)
    bpy.ops.mesh.primitive_cube_add(
        size=1,
        location=(radius * math.cos(angle),
                  radius * math.sin(angle),
                  BASE_HEIGHT + (TANK_HEIGHT - INSULATION_TOP - BASE_HEIGHT) / 2),
    )
    seam = bpy.context.active_object
    seam.name = "Pufferspeicher_Naht"
    seam.scale = (0.012, 0.006, (TANK_HEIGHT - INSULATION_TOP - BASE_HEIGHT) * 0.98)
    seam.rotation_euler = (0, 0, angle)
    bpy.ops.object.transform_apply(location=False, rotation=False, scale=True)
    bevel = seam.modifiers.new("Bevel", "BEVEL")
    bevel.width = 0.002
    bevel.segments = 3
    shade_smooth(seam)
    assign_material(seam, mat_seam)


def build_port(height, angle_deg, inner_dia, length, mat_metal, mat_cap):
    """Anschlussstutzen mit Schraubmuffe und schwarzer Schutzkappe."""
    radius_tank = TANK_DIAMETER / 2
    angle = math.radians(angle_deg)
    direction = Vector((math.cos(angle), math.sin(angle), 0))
    base_pos = Vector((radius_tank * direction.x,
                       radius_tank * direction.y,
                       height))

    outer_dia = inner_dia + 0.012
    pipe_center = base_pos + direction * (length / 2)

    bpy.ops.mesh.primitive_cylinder_add(
        vertices=48, radius=outer_dia / 2, depth=length,
        location=pipe_center,
    )
    pipe = bpy.context.active_object
    pipe.name = f"Stutzen_{int(height*1000)}_{angle_deg}"
    pipe.rotation_euler = (0, math.radians(90), angle)
    bpy.ops.object.transform_apply(location=False, rotation=True, scale=False)
    shade_smooth(pipe)
    assign_material(pipe, mat_metal)

    # Sechskant-Mutter / Anschlussflansch
    flange_pos = base_pos + direction * (length * 0.65)
    bpy.ops.mesh.primitive_cylinder_add(
        vertices=6, radius=outer_dia * 0.85, depth=length * 0.25,
        location=flange_pos,
    )
    flange = bpy.context.active_object
    flange.name = pipe.name + "_Flansch"
    flange.rotation_euler = (0, math.radians(90), angle)
    bpy.ops.object.transform_apply(location=False, rotation=True, scale=False)
    bevel = flange.modifiers.new("Bevel", "BEVEL")
    bevel.width = 0.0015
    bevel.segments = 2
    shade_smooth(flange, angle_deg=20)
    assign_material(flange, mat_metal)

    # Schwarze Schutzkappe vorne
    cap_pos = base_pos + direction * (length + 0.005)
    bpy.ops.mesh.primitive_cylinder_add(
        vertices=32, radius=outer_dia / 2 * 1.05, depth=0.012,
        location=cap_pos,
    )
    cap = bpy.context.active_object
    cap.name = pipe.name + "_Kappe"
    cap.rotation_euler = (0, math.radians(90), angle)
    bpy.ops.object.transform_apply(location=False, rotation=True, scale=False)
    bevel = cap.modifiers.new("Bevel", "BEVEL")
    bevel.width = 0.002
    bevel.segments = 3
    shade_smooth(cap)
    assign_material(cap, mat_cap)


def build_thermowell(height, angle_deg, dia, length, mat_metal):
    """Tauchhuelse fuer Thermometer (kuerzer & duenner als Stutzen)."""
    radius_tank = TANK_DIAMETER / 2
    angle = math.radians(angle_deg)
    direction = Vector((math.cos(angle), math.sin(angle), 0))
    pos = Vector((radius_tank * direction.x,
                  radius_tank * direction.y, height)) + direction * (length / 2)

    bpy.ops.mesh.primitive_cylinder_add(
        vertices=32, radius=dia / 2, depth=length, location=pos,
    )
    obj = bpy.context.active_object
    obj.name = f"Thermohuelse_{int(height*1000)}"
    obj.rotation_euler = (0, math.radians(90), angle)
    bpy.ops.object.transform_apply(location=False, rotation=True, scale=False)
    shade_smooth(obj)
    assign_material(obj, mat_metal)


def build_typenschild(mat_label):
    """Kleines silbernes Typenschild auf der Vorderseite."""
    radius_tank = TANK_DIAMETER / 2 + 0.0015
    bpy.ops.mesh.primitive_plane_add(
        size=1, location=(radius_tank, 0, 0.95),
    )
    label = bpy.context.active_object
    label.name = "Typenschild"
    label.scale = (0.001, 0.10, 0.06)
    label.rotation_euler = (0, math.radians(90), 0)
    bpy.ops.object.transform_apply(location=False, rotation=True, scale=True)
    assign_material(label, mat_label)


# ---------------------------------------------------------------------------
# Szene / Render
# ---------------------------------------------------------------------------

def build_floor(mat_floor):
    bpy.ops.mesh.primitive_plane_add(size=8, location=(0, 0, 0))
    floor = bpy.context.active_object
    floor.name = "Boden"
    assign_material(floor, mat_floor)


def setup_world_hdri(strength=1.2):
    """Studio-HDRI ueber prozedurale Sky-Textur (kein externer Asset noetig)."""
    world = bpy.context.scene.world or bpy.data.worlds.new("World")
    bpy.context.scene.world = world
    world.use_nodes = True
    nt = world.node_tree
    nt.nodes.clear()

    bg = nt.nodes.new("ShaderNodeBackground")
    out = nt.nodes.new("ShaderNodeOutputWorld")
    sky = nt.nodes.new("ShaderNodeTexSky")
    sky.sky_type = "NISHITA"
    sky.sun_elevation = math.radians(35)
    sky.sun_rotation = math.radians(135)
    bg.inputs["Strength"].default_value = strength

    nt.links.new(sky.outputs["Color"], bg.inputs["Color"])
    nt.links.new(bg.outputs["Background"], out.inputs["Surface"])


def setup_camera_and_light():
    bpy.ops.object.camera_add(
        location=(2.4, -2.6, 1.55),
        rotation=(math.radians(80), 0, math.radians(42)),
    )
    cam = bpy.context.active_object
    cam.data.lens = 65
    if hasattr(cam.data, "dof"):
        cam.data.dof.use_dof = True
        cam.data.dof.focus_distance = 3.4
        cam.data.dof.aperture_fstop = 5.6
    bpy.context.scene.camera = cam

    # Key Light
    bpy.ops.object.light_add(type="AREA", location=(2.5, -2.0, 2.6))
    key = bpy.context.active_object
    key.data.energy = 600
    key.data.size = 1.5
    key.rotation_euler = (math.radians(55), 0, math.radians(45))

    # Fill Light
    bpy.ops.object.light_add(type="AREA", location=(-2.0, -1.5, 2.0))
    fill = bpy.context.active_object
    fill.data.energy = 200
    fill.data.size = 2.0
    fill.rotation_euler = (math.radians(60), 0, math.radians(-30))


def setup_render():
    scene = bpy.context.scene
    scene.render.engine = "CYCLES"
    scene.cycles.device = "GPU" if bpy.context.preferences.addons.get("cycles") else "CPU"
    scene.cycles.samples = 256
    scene.cycles.use_denoising = True
    scene.render.resolution_x = 1600
    scene.render.resolution_y = 2000
    scene.render.resolution_percentage = 100
    scene.render.film_transparent = False
    scene.view_settings.view_transform = "Filmic"
    scene.view_settings.look = "Medium High Contrast"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    clear_scene()

    # Materialien
    mat_mantle = make_principled("Skai_Mantel", MANTLE_COLOR,
                                 roughness=0.55, sheen=0.4, clearcoat=0.05)
    add_skai_texture(mat_mantle, scale=120.0, bump_strength=0.5)

    mat_lid   = make_principled("Deckel", LID_COLOR, roughness=0.6)
    add_skai_texture(mat_lid, scale=80.0, bump_strength=0.3)

    mat_base  = make_principled("Sockel", (0.02, 0.02, 0.02, 1.0),
                                roughness=0.7)
    mat_seam  = make_principled("Naht", (0.02, 0.02, 0.03, 1.0),
                                roughness=0.45)
    mat_metal = make_principled("Edelstahl", (0.78, 0.78, 0.80, 1.0),
                                roughness=0.28, metallic=1.0)
    mat_cap   = make_principled("Schutzkappe", (0.02, 0.02, 0.02, 1.0),
                                roughness=0.55)
    mat_label = make_principled("Typenschild", (0.85, 0.85, 0.88, 1.0),
                                roughness=0.35, metallic=0.6)
    mat_floor = make_principled("Boden", (0.18, 0.18, 0.20, 1.0),
                                roughness=0.4, clearcoat=0.2)

    # Geometrie
    build_body(mat_mantle, mat_lid, mat_base)
    build_seam(mat_seam)
    for h, a, d, l in PORTS:
        build_port(h, a, d, l, mat_metal, mat_cap)
    for h, a, d, l in THERMOWELLS:
        build_thermowell(h, a, d, l, mat_metal)
    build_typenschild(mat_label)
    build_floor(mat_floor)

    # Szene
    setup_world_hdri()
    setup_camera_and_light()
    setup_render()

    print("Pufferspeicher-Szene aufgebaut. F12 fuer Render.")


if __name__ == "__main__":
    main()
