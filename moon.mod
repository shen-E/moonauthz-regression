// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "shen-E/moonauthz-regression"

version = "0.1.0"

readme = "README.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

preferred_target = "native"

description = "Configuration-driven object-level authorization regression checks for HTTP APIs."

import {
  "moonbitlang/async@0.22.4",
  "moonbitlang/x@0.5.5",
}
