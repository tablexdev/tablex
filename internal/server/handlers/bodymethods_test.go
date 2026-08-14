package handlers

import (
	"reflect"
	"testing"
)

// pageBodies is every type assigned to view.Page.Body. Add new ones here.
var pageBodies = []any{
	loginBody{}, dbStructureBody{}, createTableBody{}, designerBody{},
	editBody{}, bulkEditBody{}, exportBody{}, errorBody{}, homeBody{},
	importBody{}, routinesBody{}, triggersBody{}, eventsBody{}, dbUsersBody{},
	tableOpsBody{}, dbOpsBody{}, programEditBody{}, qbeBody{},
	tableSearchBody{}, dbSearchBody{}, serverDatabasesBody{}, varsBody{},
	processesBody{}, usersBody{}, consoleBody{}, structureBody{}, browseBody{},
}

// TestPageBodyMethodsUseValueReceivers guards a failure mode with no compiler
// signal and no local symptom: a body method declared on *T is NOT in T's
// method set, and Page.Body holds the body as a non-addressable interface
// value, so html/template cannot find it. The page compiles, the handler runs,
// every unit test passes — and the template errors at render time, which the
// server turns into a 500 for that page only.
//
// It cost a full Docker run to notice the first time (the routines list, whose
// action column asks the body whether to render). This makes it a fast local
// failure instead: a value type and its pointer must have the same method
// count, which is only true when every method uses a value receiver.
func TestPageBodyMethodsUseValueReceivers(t *testing.T) {
	for _, body := range pageBodies {
		vt := reflect.TypeOf(body)
		pt := reflect.PointerTo(vt)
		if vt.NumMethod() == pt.NumMethod() {
			continue
		}
		// Name the offenders rather than just the count.
		valueMethods := make(map[string]bool, vt.NumMethod())
		for i := range vt.NumMethod() {
			valueMethods[vt.Method(i).Name] = true
		}
		for i := range pt.NumMethod() {
			if name := pt.Method(i).Name; !valueMethods[name] {
				t.Errorf("%s.%s has a POINTER receiver; html/template cannot call it on Page.Body and the page will 500 at render time — use a value receiver",
					vt.Name(), name)
			}
		}
	}
}
