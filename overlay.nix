final: prev:

{
  # https://github.com/tytso/e2fsprogs/issues/152
  e2fsprogs-nofortify = prev.e2fsprogs.overrideAttrs (super: {
    pname = "e2fsprogs-nofortify";
    hardeningDisable = (super.hardeningDisable or [ ]) ++ [ "fortify3" ];
    nativeCheckInputs = (super.nativeCheckInputs or [ ]) ++ [ final.which ];
  });

  unblob =
    let
      pyproject_toml = (builtins.fromTOML (builtins.readFile ./pyproject.toml));
      version = pyproject_toml.project.version;
    in
    (prev.unblob.override { e2fsprogs = final.e2fsprogs-nofortify; }).overridePythonAttrs (super: {
      inherit version;

      src = final.nix-filter {
        root = ./.;
        include = [
          "pyproject.toml"
          "unblob"
          "tests"
          "README.md"
        ];
      };

      build-system = with final.python3.pkgs; [ hatchling ];

      # override disabling of 'test_all_handlers[filesystem.extfs]' from upstream
      pytestFlagsArray = [
        "--no-cov"
      ];
    });
}
