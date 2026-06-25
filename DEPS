vars = {
  'chromium_url': 'https://chromium.googlesource.com',
  'v8_revision': 'f9116f3bf9a50b0f7925daacfdc6fed503a9dbe2',
  'build_revision': '483cecced32ce8b098d65eb08eb77925afa90bec',
  'buildtools_revision': '6a18683f555b4ac8b05ac8395c29c84483ac9588',
  'gn_version': 'git_revision:103f8b437f5e791e0aef9d5c372521a5d675fabb',
  'ninja_version': 'version:3@1.12.1.chromium.4',
}

deps = {
  'v8':
    Var('chromium_url') + '/v8/v8.git' + '@' + Var('v8_revision'),
  'build':
    Var('chromium_url') + '/chromium/src/build.git' + '@' + Var('build_revision'),
  'buildtools':
    Var('chromium_url') + '/chromium/src/buildtools.git' + '@' + Var('buildtools_revision'),
  'buildtools/linux64': {
    'packages': [
      {
        'package': 'gn/gn/linux-${{arch}}',
        'version': Var('gn_version'),
      }
    ],
    'dep_type': 'cipd',
    'condition': 'host_os == "linux"',
  },
}
