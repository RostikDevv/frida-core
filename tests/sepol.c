#include <fcntl.h>
#include <gio/gio.h>
#include <glib.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>

#define FRIDA_SELINUX_ERROR frida_selinux_error_quark ()

typedef struct _FridaSELinuxRule FridaSELinuxRule;
typedef enum _FridaSELinuxErrorEnum FridaSELinuxErrorEnum;

struct _FridaSELinuxRule
{
  const gchar * source;
  const gchar * target;
  const gchar * klass;
  const gchar * permissions[16];
};

enum _FridaSELinuxErrorEnum
{
  FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND,
  FRIDA_SELINUX_ERROR_CLASS_NOT_FOUND,
  FRIDA_SELINUX_ERROR_PERMISSION_NOT_FOUND
};

static void frida_patch_policy (void);
static gboolean frida_load_policy (const gchar * filename, policydb_t * db, gchar ** data, GError ** error);
static gboolean frida_save_policy (const gchar * filename, policydb_t * db, GError ** error);
static type_datum_t * frida_ensure_type (policydb_t * db, const gchar * type_name);
static avtab_datum_t * frida_ensure_rule (policydb_t * db, const gchar * s, const gchar * t, const gchar * c, const gchar * p, GError ** error);

static const FridaSELinuxRule frida_selinux_rules[] =
{
  { "zygote", "frida", "sock_file", { "write", NULL } },
};

G_DEFINE_QUARK (frida-selinux-error-quark, frida_selinux_error)

int
main (int argc, char * argv[])
{
  frida_patch_policy ();

  g_print ("Done!\n");

  return 0;
}

static void
frida_patch_policy (void)
{
  const gchar * system_policy = "/sys/fs/selinux/policy";
  policydb_t db;
  gchar * db_data;
  sidtab_t sidtab;
  GError * error = NULL;
  int res;
  guint rule_index;

  sepol_set_policydb (&db);
  sepol_set_sidtab (&sidtab);

  if (!g_file_test (system_policy, G_FILE_TEST_EXISTS))
    return;

  if (!frida_load_policy (system_policy, &db, &db_data, &error))
  {
    g_printerr ("Unable to load SELinux policy: %s\n", error->message);
    g_error_free (error);
    return;
  }

  res = policydb_load_isids (&db, &sidtab);
  g_assert_cmpint (res, ==, 0);

  frida_ensure_type (&db, "frida");

  for (rule_index = 0; rule_index != G_N_ELEMENTS (frida_selinux_rules); rule_index++)
  {
    const FridaSELinuxRule * rule = &frida_selinux_rules[rule_index];
    const gchar * const * perm;

    for (perm = rule->permissions; *perm != NULL; perm++)
    {
      if (frida_ensure_rule (&db, rule->source, rule->target, rule->klass, *perm, &error) == NULL)
      {
        g_printerr ("Unable to add SELinux rule: %s\n", error->message);
        g_clear_error (&error);
      }
    }
  }

  if (!frida_save_policy ("/sys/fs/selinux/load", &db, &error))
  {
    g_printerr ("Unable to save SELinux policy: %s\n", error->message);
    g_clear_error (&error);
  }

  policydb_destroy (&db);
  g_free (db_data);
}

static gboolean
frida_load_policy (const gchar * filename, policydb_t * db, gchar ** data, GError ** error)
{
  policy_file_t file;
  int res;

  policy_file_init (&file);
  file.type = PF_USE_MEMORY;
  if (!g_file_get_contents (filename, &file.data, &file.len, error))
    return FALSE;

  policydb_init (db);

  res = policydb_read (db, &file, TRUE);
  g_assert_cmpint (res, ==, 0);

  *data = file.data;

  return TRUE;
}

static gboolean
frida_save_policy (const gchar * filename, policydb_t * db, GError ** error)
{
  void * data;
  size_t size;
  int res, fd;

  res = policydb_to_image (NULL, db, &data, &size);
  g_assert_cmpint (res, ==, 0);

  fd = open (filename, O_RDWR);
  if (fd == -1)
  {
    perror ("open failed");
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno), "unable to save policy to '%s'", filename);
    return FALSE;
  }

  res = write (fd, data, size);
  g_assert_cmpuint (res, ==, size);

  close (fd);

  return TRUE;
}

static type_datum_t *
frida_ensure_type (policydb_t * db, const gchar * type_name)
{
  type_datum_t * type;
  uint32_t id, i, n;
  gchar * name;

  type = hashtab_search (db->p_types.table, (char *) type_name);
  if (type != NULL)
  {
    g_print ("Already added: %s\n", type_name);
    return type;
  }

  g_print ("Adding: %s\n", type_name);

  id = ++db->p_types.nprim;
  name = strdup (type_name);

  type = malloc (sizeof (type_datum_t));

  type_datum_init (type);
  type->s.value = id;
  type->primary = TRUE;
  type->flavor = TYPE_TYPE;

  i = id - 1;
  n = db->p_types.nprim;
  db->p_type_val_to_name = realloc (db->p_type_val_to_name, n * sizeof (char *));
  db->p_type_val_to_name[i] = name;
  db->type_val_to_struct = realloc (db->type_val_to_struct, n * sizeof (type_datum_t *));
  db->type_val_to_struct[i] = type;
  db->type_attr_map = realloc (db->type_attr_map, n * sizeof (ebitmap_t));
  ebitmap_init (&db->type_attr_map[i]);
  db->attr_type_map = realloc (db->attr_type_map, n * sizeof (ebitmap_t));
  ebitmap_init (&db->attr_type_map[i]);

  hashtab_insert (db->p_types.table, name, type);

  return type;
}

static avtab_datum_t *
frida_ensure_rule (policydb_t * db, const gchar * s, const gchar * t, const gchar * c, const gchar * p, GError ** error)
{
  type_datum_t * source, * target;
  class_datum_t * klass;
  perm_datum_t * perm;
  avtab_key_t key;
  avtab_datum_t * av;

  source = hashtab_search (db->p_types.table, (char *) s);
  if (source == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "source type %s does not exist", s);
    return NULL;
  }

  target = hashtab_search (db->p_types.table, (char *) t);
  if (target == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "target type %s does not exist", t);
    return NULL;
  }

  klass = hashtab_search (db->p_classes.table, (char *) c);
  if (klass == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_CLASS_NOT_FOUND, "class %s does not exist", c);
    return NULL;
  }

  perm = hashtab_search (klass->permissions.table, (char *) p);
  if (perm == NULL && klass->comdatum != NULL)
    perm = hashtab_search (klass->comdatum->permissions.table, (char *) p);
  if (perm == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_PERMISSION_NOT_FOUND, "perm %s does not exist in class %s", p, c);
    return NULL;
  }

  key.source_type = source->s.value;
  key.target_type = target->s.value;
  key.target_class = klass->s.value;
  key.specified = AVTAB_ALLOWED;

  av = avtab_search (&db->te_avtab, &key);
  if (av == NULL)
  {
    int res;

    g_print ("Adding: %s %s %s %s\n", s, t, c, p);

    av = malloc (sizeof (avtab_datum_t));
    av->data = 1U << (perm->s.value - 1);

    res = avtab_insert (&db->te_avtab, &key, av);
    g_assert_cmpint (res, ==, 0);
  }
  else
  {
    g_print ("Already got: %s %s %s %s\n", s, t, c, p);
  }

  av->data |= 1U << (perm->s.value - 1);

  return av;
}
