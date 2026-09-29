///|
/// Entry point for the CLI or runnable program in this template.
/// Keep main focused; move logic into the library package.
/// Run with `moon run cmd/main` from the project root.
async fn main {
  let exit_code = @authz.run_cli(@env.args())
  @sys.exit(exit_code)
}
