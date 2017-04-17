package utils

import (
	"container/list"
	"github.com/kofemann/nfstop/nfs"
	"math"
	"sort"
	"strings"
)

func Aggr(l *list.List, f func(r *nfs.NfsRequest) string) *Term {

	m := make(map[string]int)

	for e := l.Front(); e != nil; e = e.Next() {
		r := e.Value.(*nfs.NfsRequest)
		m[f(r)]++
	}

	term := &Term{}
	for k, v := range m {
		e := TermElement{Key: k, Value: v}
		term.Elements = append(term.Elements, e)
	}

	sort.Sort(sort.Reverse(term))
	return term
}

func FillHisto(max int, value int, size int) string {

	hsize := math.Floor(float64(size*value) / float64(max))

	return strings.Repeat("#", int(hsize))
}
