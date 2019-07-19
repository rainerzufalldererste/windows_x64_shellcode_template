ProjectName = "child_process"
project(ProjectName)

  --Settings
  kind "ConsoleApp"
  language "C"
  flags { "StaticRuntime", "FatalWarnings" }
  
  defines { "_CRT_SECURE_NO_WARNINGS" }
  
  objdir "intermediate/obj"

  files { "src/**.c", "src/**.cpp", "src/**.h", "src/**.inl", "src/**rc" }
  files { "project.lua" }
  
  includedirs { "src" }

  targetname(ProjectName)
  targetdir "../../builds/bin"
  debugdir "../../builds/bin"

  filter { "configurations:Debug", "system:Windows" }
    ignoredefaultlibraries { "libcmt" }
  filter { }
  
filter {}
configuration {}

warnings "Extra"

filter {"configurations:Release"}
  targetname "%{prj.name}"
filter {"configurations:Debug"}
  targetname "%{prj.name}D"

filter { }
  flags { "NoPCH" }
  exceptionhandling "Off"
  rtti "Off"
  floatingpoint "Fast"

filter { "configurations:Debug*" }
  defines { "_DEBUG" }
  symbols "FastLink"

filter { "configurations:Release" }
	defines { "NDEBUG" }
	optimize "Speed"
	flags { "NoFramePointer", "NoBufferSecurityCheck", "NoIncrementalLink" }
  editandcontinue "Off"
  symbols "On"
