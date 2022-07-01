project('lightecdh', 'c', version : '0.1', default_options : ['warning_level=3'])

lightecdh_curves = static_library('lightecdh_curves', 'src/lightecdh_curves.c')
lightecdh_random = static_library('lightecdh_random', 'src/lightecdh_random.c')
lightecdh = static_library('lightecdh', 'src/lightecdh.c',
  link_with: [lightecdh_curves])
lightecdhbit = static_library('lightecdhbit', 'src/lightecdh_bitmath.c',
  link_with: [lightecdh, lightecdh_curves])
lightecdhpoint = static_library('lightecdhpoint', 'src/lightecdh_pointmath.c', 'src/lightecdh_curves.c',
  link_with: [lightecdh, lightecdh_curves])

test_lightecdh = executable('test_lightecdh', 'src/test_lightecdh.c', 'src/lightecdh_curves.c',
  link_with: [lightecdh, lightecdhbit, lightecdhpoint, lightecdh_curves, lightecdh_random],
  install : true)

test('keys', test_lightecdh, args: ['keys'])
test('secret', test_lightecdh, args: ['secret'])
test('sign', test_lightecdh, args: ['sign'])
test('verify', test_lightecdh, args: ['verify'])