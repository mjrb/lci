#import "lolffi.h"
/* in lolffi.h
struct {
	ValueObject *cfunc;
	char* name;
	FuncList *next;
} FuncList;
*/

ReturnObject *func(ValueObject **args, int argc, ScopeObject scope) {
	    return createIntObject(3);
}

LOL_IMPORT_LIST;
LOL_IMPORT("NAME", &func, 0);
LOL_IMPORT_END;

/* generated
FuncList *LOL_MAIN()
{
	FuncList *list = NULL;
	list = funcListAppend(list, "NAME", createFFIFuncValueObject(&func, 0));
	return list;
}
*/
