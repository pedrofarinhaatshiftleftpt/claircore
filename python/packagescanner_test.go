package python_test

import (
	"context"
	"net/http"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/test/fetch"
	"github.com/quay/claircore/test/log"
)

// TestScan runs the python scanner over some layers known to have python
// packages installed.
func TestScan(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	for _, tc := range scanTable {
		t.Run(path.Base(tc.Name), tc.Run(ctx))
	}
}

type scanTestcase struct {
	Domain string
	Name   string
	Hash   string
	Want   []*claircore.Package
}

func (tc scanTestcase) Digest() claircore.Digest {
	d, err := claircore.ParseDigest(tc.Hash)
	if err != nil {
		panic(err)
	}
	return d
}

func (tc scanTestcase) Run(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx = log.TestLogger(ctx, t)
		l := &claircore.Layer{
			Hash: tc.Digest(),
		}
		s := &python.Scanner{}
		n, err := fetch.Layer(ctx, t, http.DefaultClient, tc.Domain, tc.Name, tc.Digest())
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		l.SetLocal(n.Name())

		got, err := s.Scan(ctx, l)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("found %d packages", len(got))
		if !cmp.Equal(tc.Want, got) {
			t.Error(cmp.Diff(tc.Want, got))
		}
	}
}

var scanTable = []scanTestcase{
	{
		Domain: "docker.io",
		Name:   "library/hylang",
		Hash:   "sha256:a96bd05c55b4e8d8944dbc6567e567dd48442dc65a7e8097fe7510531d4bbb1b",
		Want: []*claircore.Package{
			&claircore.Package{
				Name:      "appdirs",
				Version:   "1.4.3",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "args",
				Version:   "0.1.0",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "astor",
				Version:   "0.8.1",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "clint",
				Version:   "0.5.1",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "funcparserlib",
				Version:   "0.3.6",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "hy",
				Version:   "0.17.0",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "rply",
				Version:   "0.7.7",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
		},
	},
	{
		Domain: "docker.io",
		Name:   "pythonpillow/fedora-30-amd64",
		Hash:   "sha256:cb257051a8e2e33f5216524539bc2bf2e7b29c42d11ceb08caee36e446235c00",
		Want: []*claircore.Package{
			&claircore.Package{
				Name:      "attrs",
				Version:   "19.3.0",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "cffi",
				Version:   "1.13.2",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "coverage",
				Version:   "5.0.3",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "importlib-metadata",
				Version:   "1.5.0",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "more-itertools",
				Version:   "8.1.0",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "numpy",
				Version:   "1.18.1",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "olefile",
				Version:   "0.46",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "packaging",
				Version:   "20.1",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "pip",
				Version:   "20.0.2",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "pluggy",
				Version:   "0.13.1",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "py",
				Version:   "1.8.1",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "pycparser",
				Version:   "2.19",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "pyparsing",
				Version:   "2.4.6",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "pytest",
				Version:   "5.3.4",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "pytest-cov",
				Version:   "2.8.1",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "setuptools",
				Version:   "45.1.0",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "six",
				Version:   "1.14.0",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "wcwidth",
				Version:   "0.1.8",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "wheel",
				Version:   "0.34.1",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "zipp",
				Version:   "2.1.0",
				Kind:      "source",
				PackageDB: "vpy3/lib/python3.7/site-packages",
			},
		},
	},
	{
		Domain: "docker.io",
		Name:   "pythondiscord/seasonalbot",
		Hash:   "sha256:109a55eba749c02eb6a4533eba12d8aa02a68417ff96886d049798ed5653a156",
		Want: []*claircore.Package{
			&claircore.Package{
				Name:      "Pillow",
				Version:   "6.2.1",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "aiodns",
				Version:   "2.0.0",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "aiohttp",
				Version:   "3.5.4",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "arrow",
				Version:   "0.15.4",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "async-timeout",
				Version:   "3.0.1",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "attrs",
				Version:   "19.3.0",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "beautifulsoup4",
				Version:   "4.8.1",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "cffi",
				Version:   "1.13.2",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "chardet",
				Version:   "3.0.4",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "discord.py",
				Version:   "1.2.5",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "fuzzywuzzy",
				Version:   "0.17.0",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "idna",
				Version:   "2.8",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "multidict",
				Version:   "4.6.1",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "pycares",
				Version:   "3.0.0",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "pycparser",
				Version:   "2.19",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "python-dateutil",
				Version:   "2.8.1",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "pytz",
				Version:   "2019.3",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "six",
				Version:   "1.13.0",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "soupsieve",
				Version:   "1.9.5",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "websockets",
				Version:   "6.0",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
			&claircore.Package{
				Name:      "yarl",
				Version:   "1.4.1",
				Kind:      "source",
				PackageDB: "usr/local/lib/python3.7/site-packages",
			},
		},
	},
}
