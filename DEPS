vars = {
  'chromium_url': 'https://chromium.googlesource.com',
  'v8_revision': 'f9116f3bf9a50b0f7925daacfdc6fed503a9dbe2',
  'build_revision': '483cecced32ce8b098d65eb08eb77925afa90bec',
  'buildtools_revision': '6a18683f555b4ac8b05ac8395c29c84483ac9588',
}

deps = {
  'v8':
    Var('chromium_url') + '/v8/v8.git' + '@' + Var('v8_revision'),
  'build':
    Var('chromium_url') + '/chromium/src/build.git' + '@' + Var('build_revision'),
  'buildtools':
    Var('chromium_url') + '/chromium/src/buildtools.git' + '@' + Var('buildtools_revision'),
}
