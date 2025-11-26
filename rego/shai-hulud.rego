package fremkit

namefmt(name, pkg) := concat("@", [replace(name, "node_modules/", ""), pkg.version])
resolved(pkg) := object.get(pkg, "resolved", "")
in_bad_pkg_list(name_ver) := name_ver in data.known_bad_packages

bad_packages contains pkg if {
	walk(input.packages, [_, value])

	some name, dep in value
	name != ""
	pkg := namefmt(name, dep)
	in_bad_pkg_list(pkg)
}

default detected := false

detected if count(bad_packages) > 0
