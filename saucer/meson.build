saucer_sources = [
  'saucer.vala',
  'saucer-glue.c',
]

extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  symlist = 'frida-saucer.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), symlist)]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'frida-saucer.version'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), symscript)]
  extra_link_depends += [symscript]
endif

raw_saucer = executable('frida-saucer-raw', saucer_sources,
  vala_args: ['--pkg=posix'],
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  dependencies: [core_dep],
)

custom_target('frida-saucer',
  input: [
    raw_saucer,
    'frida-saucer.xcent',
  ],
  output: 'frida-saucer',
  command: [
    files('post-process.sh'),
    '@INPUT@',
    '@OUTPUT@',
    host_os,
    meson.get_cross_binary('strip', 'strip'),
    get_option('strip').to_string(),
  ],
  install: true,
  install_dir: get_option('bindir'),
)
