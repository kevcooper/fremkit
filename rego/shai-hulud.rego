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

deny[msg] if {
	count(bad_packages) > 0
	some pkg in bad_packages
	msg := sprintf("The npm package '%s' is a known malicious package", [pkg])
}
