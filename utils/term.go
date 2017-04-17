package utils

type TermElement struct {
	Key   string
	Value int
}

type Term struct {
	Elements []TermElement
}

func (t *Term) Len() int {
	return len(t.Elements)
}
func (t *Term) Swap(i, j int) {
	t.Elements[i], t.Elements[j] = t.Elements[j], t.Elements[i]
}
func (t *Term) Less(i, j int) bool {
	return t.Elements[i].Value < t.Elements[j].Value
}

func (t *Term) Sum() int {
	var sum int
	for i := 0; i < len(t.Elements); i++ {
		sum += t.Elements[i].Value
	}
	return sum
}
