solution "shellcode_template"
  
  editorintegration "On"
  platforms { "x64" }
  configurations { "Debug", "Release" }

  dofile "shellcode_template/project.lua"
  
  group "example"
    dofile "example/host_process/project.lua"
    dofile "example/child_process/project.lua"
