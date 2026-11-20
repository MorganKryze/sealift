#!/bin/sh
# Proves, on the lab's Nexus, the path the import takes to publish a wheel:
# read the repository's simple page before, upload through the components
# API, read the page and the file back, then pip downloads it from the
# air-gapped side. It then removes each privilege of the sealift-import role
# in turn and names the call that breaks. Run it from lab/ after setup.sh:
# `sh scripts/pypi-proof.sh`. It prints one Markdown table row per check and
# exits 1 when a check of steps 1 to 8 or the cleanup fails.
#
# Credentials reach curl through `-K -` on stdin, never on a command line.
set -u
cd "$(dirname "$0")/.."
NEXUS=http://127.0.0.1:18441
REPO=pypi
ADMIN_PASSWORD=${NEXUS_PASSWORD:-lab-admin-password}
IMPORT_PASSWORD=$(cat import/nexus-password)
ROLE=sealift-import

for tool in curl jq shasum docker; do
	command -v "$tool" >/dev/null || { echo "pypi-proof needs $tool" >&2; exit 2; }
done

work=$(mktemp -d)
role_saved=
restore_role() {
	if [ -n "$role_saved" ]; then
		call admin /dev/null -X PUT -H 'Content-Type: application/json' \
			--data "$role_saved" "$NEXUS/service/rest/v1/security/roles/$ROLE" >/dev/null
	fi
	rm -rf "$work"
}
trap restore_role EXIT
trap 'exit 130' INT TERM

failed=0
row() { # step, check, result, detail
	printf '| %s | %s | %s | %s |\n' "$1" "$2" "$3" "$4"
	if [ "$3" = FAIL ]; then failed=$((failed + 1)); fi
}

# call <admin|import> <output file> <curl arguments>: prints the HTTP status,
# 000 when Nexus does not answer.
call() {
	case $1 in
	admin) cred="admin:$ADMIN_PASSWORD" ;;
	import) cred="$ROLE:$IMPORT_PASSWORD" ;;
	esac
	dest=$2
	shift 2
	[ "$dest" = /dev/null ] || rm -f "$dest"
	printf 'user = "%s"\n' "$(printf '%s' "$cred" | sed 's/[\\"]/\\&/g')" |
		curl -s -K - --max-time 60 -o "$dest" -w '%{http_code}' "$@"
}

# Text read from Nexus or pip enters the table without control characters,
# without pipes, and cut to 300 characters.
clean() { tr -d '\000-\037\177' | tr '|' '/' | cut -c1-300; }

sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }

# anchor <page> <file>: the page's anchor whose text is the file name, on one
# line. Nexus spreads an anchor over several lines.
anchor() {
	[ -f "$1" ] || return 0
	tr '\n\r\t' '   ' <"$1" | grep -o '<a [^>]*>[^<]*</a>' | awk -v f="$2" '{
		t = $0; sub(/^<a [^>]*>/, "", t); sub(/<\/a>$/, "", t); gsub(/^ +| +$/, "", t)
		if (t == f) { print; exit }
	}'
}

# body <file>: the start of an answer's body, empty when there is none.
body() { if [ -f "$1" ]; then clean <"$1" | cut -c1-120; fi; }

# Public wheels, each released more than 14 days before this proof was
# written: a pure one, one whose file name uses an underscore for a hyphenated
# project, a cp311 manylinux one with a compound platform tag, and one for the
# rights checks. Fields: normalized project, version, file, sha256, URL.
wheel() {
	case $1 in
	six) set -- six 1.16.0 six-1.16.0-py2.py3-none-any.whl \
		8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254 \
		https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl ;;
	mypy-extensions) set -- mypy-extensions 1.0.0 mypy_extensions-1.0.0-py3-none-any.whl \
		4392f6c0eb8a5668a69e23d168ffa70f0be9ccfd32b5cc2d26a34ae5b844552d \
		https://files.pythonhosted.org/packages/2a/e2/5d3f6ada4297caebe1a2add3b126fe800c96f56dbe5d1988a2cbe0b267aa/mypy_extensions-1.0.0-py3-none-any.whl ;;
	markupsafe) set -- markupsafe 2.1.5 MarkupSafe-2.1.5-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl \
		b91c037585eba9095565a3556f611e3cbfaa42ca1e865f7b8015fe5c7336d5a5 \
		https://files.pythonhosted.org/packages/97/18/c30da5e7a0e7f4603abfc6780574131221d9148f323752c2755d48abad30/MarkupSafe-2.1.5-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl ;;
	idna) set -- idna 3.6 idna-3.6-py3-none-any.whl \
		c05567e9c24a6b9faaa835c4821bad0590fbb9d5779e7caa6e1cc4978e7eb24f \
		https://files.pythonhosted.org/packages/c2/e7/a82b05cf63a603df6e68d59ae6a68bf5064484a0718ea5033660af4b54a9/idna-3.6-py3-none-any.whl ;;
	esac
	project=$1 version=$2 file=$3 sum=$4 url=$5
}
WHEELS="six mypy-extensions markupsafe"
sixtarget=
ALL="$WHEELS idna"

# Deletes every component of the repository whose normalized name is one of
# the proof's; prints how many it deleted, or "error".
delete_components() {
	names=$1
	token= deleted=0
	while :; do
		status=$(call admin "$work/components.json" \
			"$NEXUS/service/rest/v1/components?repository=$REPO${token:+&continuationToken=$token}")
		[ "$status" = 200 ] || { echo error; return; }
		for id in $(jq -r --arg names " $names " '.items[]
			| (.name | ascii_downcase | gsub("[-_.]+"; "-")) as $n
			| select($names | contains(" " + $n + " ")) | .id' "$work/components.json"); do
			status=$(call admin /dev/null -X DELETE "$NEXUS/service/rest/v1/components/$id")
			[ "$status" = 204 ] || { echo error; return; }
			deleted=$((deleted + 1))
		done
		token=$(jq -r '.continuationToken // empty' "$work/components.json")
		[ -n "$token" ] || break
	done
	echo "$deleted"
}

for w in $ALL; do
	wheel "$w"
	if ! curl -sf --proto =https --max-time 120 -o "$work/$file" "$url" </dev/null ||
		[ "$(sha256 "$work/$file")" != "$sum" ]; then
		echo "$file: the download failed or its sha256 differs from $sum" >&2
		exit 2
	fi
done

leftover=$(delete_components "$ALL")
[ "$leftover" != error ] || { echo "Nexus refused the admin's cleanup of an earlier run" >&2; exit 2; }

echo '| Step | Check | Result | Detail |'
echo '| --- | --- | --- | --- |'
[ "$leftover" = 0 ] || row 0 "components left by an earlier run" INFO "$leftover deleted as admin"

# Step 1: the repository list the import reads to check the target.
status=$(call import "$work/repos.json" "$NEXUS/service/rest/v1/repositories")
listed=$(jq -r --arg r "$REPO" '[.[] | select(.name == $r)][0] | if . then "\(.format) \(.type)" else "absent" end' \
	"$work/repos.json" 2>/dev/null || echo unreadable)
if [ "$status" = 200 ] && [ "$listed" = "pypi hosted" ]; then r=PASS; else r=FAIL; fi
row 1 "repository list as $ROLE" "$r" "status $status, $REPO is $listed"

# upload <file>: prints the status of a components API upload as the import.
upload() {
	call import "$work/upload.out" -X POST -F "pypi.asset=@$work/$1" \
		"$NEXUS/service/rest/v1/components?repository=$REPO"
}

for w in $WHEELS; do
	wheel "$w"
	page="$NEXUS/repository/$REPO/simple/$project/"

	# Step 2: the simple page before the upload.
	status=$(call import "$work/before.html" "$page")
	case $status in
	404) r=PASS ;;
	200) if [ -n "$(anchor "$work/before.html" "$file")" ]; then r=FAIL; else r=PASS; fi ;;
	*) r=FAIL ;;
	esac
	row 2 "$project: simple page before the upload" "$r" "status $status"

	# Step 3: the upload.
	status=$(upload "$file")
	if [ "$status" = 204 ]; then r=PASS; else r=FAIL; fi
	row 3 "$project: upload with the pypi.asset field" "$r" "status $status $(body "$work/upload.out")"

	# Step 4: the simple page after the upload lists the exact file.
	status=$(call import "$work/after.html" "$page")
	tag=$(anchor "$work/after.html" "$file")
	href=$(printf '%s' "$tag" | sed -n 's/.*href="\([^"]*\)".*/\1/p')
	fragment=$(printf '%s' "$href" | sed -n 's/.*#sha256=\([0-9a-f]*\).*/\1/p')
	if [ -z "$fragment" ]; then frag="no #sha256= fragment"
	elif [ "$fragment" = "$sum" ]; then frag="#sha256= equal"
	else frag="#sha256= differs: $fragment"; fi
	data=$(printf '%s' "$tag" | grep -o 'data-[a-z-]*="[^"]*"' | tr '\n' ' ' | clean)
	if [ "$status" = 200 ] && [ -n "$href" ] && [ "$frag" != "#sha256= differs: $fragment" ]; then r=PASS; else r=FAIL; fi
	row 4 "$project: simple page lists $file" "$r" \
		"status $status, href \`$(printf '%s' "$href" | clean)\`, $frag, data attributes: ${data:-none}"

	# Step 5: the linked file holds the uploaded bytes.
	link=${href%%#*}
	case $link in
	http://* | https://*) target=$link ;;
	/*) target=$NEXUS$link ;;
	*) target=$page$link ;;
	esac
	[ "$project" != six ] || sixtarget=$target
	if [ -n "$link" ]; then
		status=$(call import "$work/back.whl" "$target")
		got=$(sha256 "$work/back.whl" 2>/dev/null)
	else
		status=none got=none
	fi
	if [ "$status" = 200 ] && [ "$got" = "$sum" ]; then r=PASS; else r=FAIL; fi
	row 5 "$project: linked file read back" "$r" "status $status, sha256 ${got:-none}, local $sum"

	# Step 6: the asset path the search gives, by normalized name, then by
	# the file name's distribution part.
	path= asked=
	for name in "$project" "${file%%-*}"; do
		status=$(call import "$work/assets.json" "$NEXUS/service/rest/v1/search/assets?repository=$REPO&name=$name")
		path=$(jq -r --arg f "$file" '[.items[].path | select(endswith("/" + $f))][0] // empty' "$work/assets.json" 2>/dev/null)
		if [ -n "$path" ]; then asked=$name; break; fi
	done
	if [ -n "$path" ]; then
		dir=$(printf '%s' "${path#/}" | cut -d/ -f2)
		if [ "$dir" = "$project" ]; then norm="normalized"; else norm="not normalized ($dir)"; fi
		row 6 "$project: asset path from the search" PASS "name=$asked, path \`$(printf '%s' "$path" | clean)\`, project $norm"
	else
		row 6 "$project: asset path from the search" FAIL "status $status, no asset ends with $file"
	fi

	# Step 7: the same file again, on a repository that allows one write.
	status=$(upload "$file")
	case $status in
	400 | 409) r=PASS ;;
	2*) r=INFO ;;
	*) r=FAIL ;;
	esac
	row 7 "$project: the same file posted again" "$r" "status $status $(body "$work/upload.out")"
done

# The simple API's JSON form, which pip asks for first.
wheel six
status=$(call import "$work/page.json" -H 'Accept: application/vnd.pypi.simple.v1+json' \
	-D "$work/page.headers" "$NEXUS/repository/$REPO/simple/$project/")
ctype=$(grep -i '^content-type:' "$work/page.headers" | cut -d' ' -f2- | clean)
if jq -e . "$work/page.json" >/dev/null 2>&1; then json=JSON; else json="not JSON"; fi
row 4 "six: simple page with Accept application/vnd.pypi.simple.v1+json" INFO "status $status, content type $ctype, body $json"

# Step 8: pip on the air-gapped side downloads each wheel from Nexus. The
# index is plain HTTP on the internal network, which pip uses only for a
# trusted host.
for w in $WHEELS; do
	wheel "$w"
	out=$(docker compose run --rm -T pip-shell sh -c '
		pip download --quiet --no-cache-dir --disable-pip-version-check --no-deps \
			--only-binary :all: --trusted-host nexus \
			--index-url http://nexus:8081/repository/pypi/simple/ -d /tmp/w "$1==$2" &&
		cd /tmp/w && sha256sum -- *' sh "$project" "$version" </dev/null 2>&1)
	got=$(printf '%s\n' "$out" | grep -F "  $file" | cut -d' ' -f1)
	if [ "$got" = "$sum" ]; then
		row 8 "$project: pip download from pip-shell" PASS "$file, sha256 equal"
	else
		row 8 "$project: pip download from pip-shell" FAIL "$(printf '%s\n' "$out" | tail -n 1 | clean)"
	fi
done

# Step 9: each privilege of the role removed in turn. As the import: the
# repository list, the six page and its file, then an upload of idna.
status=$(call admin "$work/role.json" "$NEXUS/service/rest/v1/security/roles/$ROLE")
if [ "$status" != 200 ]; then
	row 9 "read the $ROLE role as admin" FAIL "status $status"
else
	role_saved=$(jq -c '{id, name, description, privileges, roles}' "$work/role.json")
	wheel six
	sixpage="$NEXUS/repository/$REPO/simple/$project/"
	for p in browse read add edit upload; do
		case $p in
		upload) priv=nx-component-upload ;;
		*) priv=nx-repository-view-$REPO-$REPO-$p ;;
		esac
		reduced=$(printf '%s' "$role_saved" | jq -c --arg p "$priv" '.privileges -= [$p]')
		status=$(call admin /dev/null -X PUT -H 'Content-Type: application/json' --data "$reduced" \
			"$NEXUS/service/rest/v1/security/roles/$ROLE")
		if [ "$status" != 204 ]; then
			row 9 "without $priv" FAIL "the role update answered $status"
			continue
		fi
		s1=$(call import "$work/repos.json" "$NEXUS/service/rest/v1/repositories")
		l1=$(jq -r --arg r "$REPO" 'if any(.[]; .name == $r) then "listed" else "absent" end' "$work/repos.json" 2>/dev/null || echo unreadable)
		s4=$(call import "$work/page.html" "$sixpage")
		if [ -n "$(anchor "$work/page.html" "$file")" ]; then l4=listed; else l4="not listed"; fi
		if [ -n "$sixtarget" ]; then s5=$(call import /dev/null "$sixtarget"); else s5=none; fi
		wheel idna
		s3=$(upload "$file")
		wheel six
		broken=
		[ "$s1" = 200 ] && [ "$l1" = listed ] || broken="${broken}list, "
		[ "$s4" = 200 ] && [ "$l4" = listed ] || broken="${broken}page, "
		[ "$s5" = 200 ] || broken="${broken}file, "
		[ "$s3" = 204 ] || broken="${broken}upload, "
		broken=${broken%, }
		row 9 "without $priv" INFO "list $s1 ($REPO $l1), six page $s4 ($l4), six file $s5, idna upload $s3 $(body "$work/upload.out"); breaks: ${broken:-nothing}"
		deleted=$(delete_components idna)
		status=$(call admin /dev/null -X PUT -H 'Content-Type: application/json' --data "$role_saved" \
			"$NEXUS/service/rest/v1/security/roles/$ROLE")
		if [ "$status" != 204 ] || [ "$deleted" = error ]; then
			row 9 "restore after $priv" FAIL "role update $status, idna deleted: $deleted"
		fi
	done
	role_saved=
fi

# Step 10: the repository left empty for the next lab run.
deleted=$(delete_components "$ALL")
status=$(call admin "$work/components.json" "$NEXUS/service/rest/v1/components?repository=$REPO")
left=$(jq '.items | length' "$work/components.json" 2>/dev/null || echo unknown)
if [ "$deleted" != error ] && [ "$status" = 200 ] && [ "$left" = 0 ]; then r=PASS; else r=FAIL; fi
row 10 "the proof's components deleted as admin" "$r" "deleted $deleted, $left left in $REPO"

[ "$failed" = 0 ]
