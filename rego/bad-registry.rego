package fremkit

namefmt(name, pkg) := concat("@", [replace(name, "node_modules/", ""), pkg.version])
resolved(pkg) := object.get(pkg, "resolved", "")

has_approved_registry(pkg) if {
	"resolved" in object.keys(pkg)
	startswith(resolved(pkg), concat("", [
		trim(data.allowed_registries[_], "/"),
		"/",
	]))
}

bad_packages contains pkg if {
	walk(input.packages, [_, value])

	some name, dep in value

	name != ""
	not has_approved_registry(dep)
	name_ver := namefmt(name, dep)
	pkg := {
		"name": name_ver,
		"resolved": resolved(dep),
	}
}

deny[msg] if {
	count(bad_packages) > 0
	some pkg in bad_packages
	msg := sprintf("The npm package '%s' was resolved from unapproved registry '%s'", [pkg.name, pkg.resolved])
}
