#include "binding.h"
#include "inet.h"  /* for sockets */
#include <mongoc/mongoc.h>

char *sanitizeInput(char *input)
{
	unsigned int size = 16;
	unsigned int cur = 0;
	char *temp = malloc(sizeof(char) * size);
	int pos = 0;
	int c;
	void *mem = NULL;
	while (c = input[pos]) {
		temp[cur] = (char)c;
		cur++;
		pos++;
		/* Reserve space to escape colon in input */
		if (c == ':') {
			cur++;
		}
		if (cur > size - 1) {
			/* Increase buffer size */
			size *= 2;
			mem = realloc(temp, sizeof(char) * size);
			if (!mem) {
				perror("realloc");
				free(temp);
				return NULL;
			}
			temp = mem;
		}
		/* Escape colon in input */
		if (c == ':') {
			temp[cur - 1] = ':';
		}
	}
	temp[cur] = '\0';
	return temp;
}

ValueObject *getArg(struct scopeobject *scope, char *name)
{
	IdentifierNode *id = createIdentifierNode(IT_DIRECT, (void *)copyString(name), NULL, NULL, 0);
	ValueObject *val = getScopeValue(scope, scope, id);
	deleteIdentifierNode(id);
	return val;
}

ReturnObject *iopenWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "addr");
	ValueObject *arg2 = getArg(scope, "port");
	char *addr = getString(castStringImplicit(arg1, scope));
	int port = getInteger(arg2);

	inet_host_t *h = malloc(sizeof(inet_host_t));
	if (!strcmp(addr, "ANY")) {
		inet_open(h, IN_PROT_TCP, (const char *)IN_ADDR_ANY, port);
	} else {
		inet_open(h, IN_PROT_TCP, addr, port);
	}

	ValueObject *ret = createBlobValueObject(h);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *ilookupWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "addr");
	char *addr = getString(castStringImplicit(arg1, scope));

	char *h = inet_lookup(addr);

	ValueObject *ret = createStringValueObject(h);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *iacceptWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "local");
	inet_host_t *host = (inet_host_t *)getBlob(arg1);

	inet_host_t *h = malloc(sizeof(inet_host_t));
	inet_accept(h, host);

	ValueObject *ret = createBlobValueObject(h);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *iconnectWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "local");
	ValueObject *arg2 = getArg(scope, "addr");
	ValueObject *arg3 = getArg(scope, "port");
	inet_host_t *host = (inet_host_t *)getBlob(arg1);
	char *addr = getString(castStringImplicit(arg2, scope));
	int port = getInteger(arg3);

	inet_host_t *h = malloc(sizeof(inet_host_t));
	inet_setup(h, IN_PROT_TCP, addr, port);
	inet_connect(host, h);

	ValueObject *ret = createBlobValueObject(h);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *icloseWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "local");
	inet_host_t *host = (inet_host_t *)getBlob(arg1);

	inet_close(host);

	ValueObject *ret = createBlobValueObject(host);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *isendWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "local");
	ValueObject *arg2 = getArg(scope, "remote");
	ValueObject *arg3 = getArg(scope, "data");
	inet_host_t *local = (inet_host_t *)getBlob(arg1);
	inet_host_t *remote = (inet_host_t *)getBlob(arg2);
	char *data = getString(castStringImplicit(arg3, scope));

	int n = inet_send(local, remote, data, strlen(data));

	ValueObject *ret = createIntegerValueObject(n);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *ireceiveWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "local");
	ValueObject *arg2 = getArg(scope, "remote");
	ValueObject *arg3 = getArg(scope, "amount");
	inet_host_t *local = (inet_host_t *)getBlob(arg1);
	inet_host_t *remote = (inet_host_t *)getBlob(arg2);
	int amount = getInteger(arg3);

	char *data = malloc(sizeof(char) * (amount + 1));
	int len = inet_receive(remote, local, data, amount, -1);
	data[len] = '\0';

	char *sanitized = sanitizeInput(data);
	free(data);

	ValueObject *ret = createStringValueObject(sanitized);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *fopenWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "filename");
	ValueObject *arg2 = getArg(scope, "mode");
	char *filename = getString(castStringImplicit(arg1, scope));
	char *mode = getString(castStringImplicit(arg2, scope));

	FILE *f = fopen(filename, mode);

	ValueObject *ret = createBlobValueObject(f);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *freadWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "file");
	ValueObject *arg2 = getArg(scope, "length");
	FILE *file = (FILE *)getBlob(arg1);
	int length = getInteger(arg2);

	char *buf = malloc(sizeof(char) * (length + 1));
	int len = fread(buf, 1, length, file);
	buf[len] = '\0';

	char *sanitized = sanitizeInput(buf);
	free(buf);

	ValueObject *ret = createStringValueObject(sanitized);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *fwriteWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "file");
	ValueObject *arg2 = getArg(scope, "data");
	FILE *file = (FILE *)getBlob(arg1);
	char *data = getString(castStringExplicit(arg2, scope));

	fwrite(data, 1, strlen(data), file);

	return createReturnObject(RT_DEFAULT, NULL);
}

ReturnObject *fcloseWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "file");
	FILE *file = (FILE *)getBlob(arg1);

	fclose(file);

	return createReturnObject(RT_DEFAULT, NULL);
}

ReturnObject *ferrorWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "file");
	FILE *file = (FILE *)getBlob(arg1);

	ValueObject *ret = createBooleanValueObject(file == NULL || ferror(file));
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *rewindWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "file");
	FILE *file = (FILE *)getBlob(arg1);

	rewind(file);

	return createReturnObject(RT_DEFAULT, NULL);
}

ReturnObject *strlenWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "string");
	char *string = getString(castStringImplicit(arg1, scope));

	size_t len = strlen(string);

	ValueObject *ret = createIntegerValueObject((long long)len);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *stratWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "string");
	ValueObject *arg2 = getArg(scope, "position");
	char *string = getString(castStringImplicit(arg1, scope));
	long long position = getInteger(arg2);

	char *temp = malloc(sizeof(char) * 2);
	temp[0] = string[position];
	temp[1] = 0;

	ValueObject *ret = createStringValueObject(temp);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *srandWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "seed");
	int seed = getInteger(arg1);

	srand(seed);

	return createReturnObject(RT_DEFAULT, NULL);
}

ReturnObject *randWrapper(struct scopeobject *scope)
{
	ValueObject *arg1 = getArg(scope, "max");
	unsigned int max = getInteger(arg1);

	unsigned int val = (rand() % max);

	ValueObject *ret = createIntegerValueObject(val);
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *insertOneWrapper(struct scopeobject *scope)
{
	ValueObject *collObject = getArg(scope, "coll");
	if (collObject->type != VT_BLOB) {
		fprintf(stderr, "mongodb: insert one coll must be BLOB\n");
		return NULL;
	}
	ValueObject *docObject = getArg(scope, "doc");
	if (docObject->type != VT_ARRAY) {
		fprintf(stderr, "mongodb: insert one doc must be object\n");
		return NULL;
	}
	mongoc_collection_t *coll = (mongoc_collection_t *)getBlob(collObject);
	bson_t *doc = scope2bson(getArray(docObject));
	bson_error_t error;
	int result = mongoc_collection_insert_one(coll, doc, NULL, NULL, &error);
	bson_destroy(doc);
	return createReturnObject(RT_RETURN, createBooleanValueObject(result));
}

ReturnObject *insertManyWrapper(struct scopeobject *scope)
{
	return NULL;
}

ReturnObject *findWrapper(struct scopeobject *scope)
{
	ValueObject *collObject = getArg(scope, "coll");
	if (collObject->type != VT_BLOB) {
		fprintf(stderr, "mongodb: find coll must be BLOB\n");
		return NULL;
	}
	ValueObject *queryObject = getArg(scope, "query");
	if (queryObject->type != VT_ARRAY) {
		fprintf(stderr, "mongodb: find query must be object\n");
		return NULL;
	}
	mongoc_collection_t *coll = (mongoc_collection_t *)getBlob(collObject);
	bson_t *query = scope2bson(getArray(queryObject));
	bson_error_t error;
	mongoc_cursor_t *cur = mongoc_collection_find_with_opts(coll,
								query,
								NULL,
								NULL);
	const bson_t *doc = NULL;
	ScopeObject *result = createScopeObject(NULL);
	int len = 0;
	char *name = NULL;
	IdentifierNode *id = NULL;
	while (mongoc_cursor_next(cur, &doc)) {
		asprintf(&name, "%d", len);
		id = MOVKEY(name);

		if (!createScopeValue(result, result, id)) {
			fprintf(stderr, "mongodb: find failed to add item to array\n");
			return NULL;
		}
		if (!updateScopeValue(result, result, id, createArrayValueObject(bson2scope(doc)))) {
			fprintf(stderr, "mongodb: find failed to add item to array\n");
			return NULL;
		}
		
		if (id) deleteIdentifierNode(id);
		len++;
	}
	id = CPYKEY("LEN");
	if (!createScopeValue(result, result, id)) {
		fprintf(stderr, "mongodb: find failed to add item to array\n");
		return NULL;
	}
	if (!updateScopeValue(result, result, id, createIntegerValueObject(len))) {
		fprintf(stderr, "mongodb: find failed to add item to array\n");
		return NULL;
	}
	if (id) deleteIdentifierNode(id);
	return createReturnObject(RT_RETURN, createArrayValueObject(result));
}

ReturnObject *updateOneWrapper(struct scopeobject *scope)
{
	ValueObject *collObject = getArg(scope, "coll");
	if (collObject->type != VT_BLOB) {
		fprintf(stderr, "mongodb: update one coll must be BLOB\n");
		return NULL;
	}
	ValueObject *queryObject = getArg(scope, "query");
	if (queryObject->type != VT_ARRAY) {
		fprintf(stderr, "mongodb: update one doc must be object\n");
		return NULL;
	}
	bson_t *query = scope2bson(getArray(queryObject));
	ValueObject *updateObject = getArg(scope, "update");
	if (updateObject->type != VT_ARRAY) {
		fprintf(stderr, "mongodb: update one doc must be object\n");
		return NULL;
	}
	bson_t *update = scope2bson(getArray(updateObject));
	mongoc_collection_t *coll = (mongoc_collection_t *)getBlob(collObject);
	bson_error_t error;
	int result = mongoc_collection_update_one(coll, query, update, NULL, NULL, &error);
	bson_destroy(query);
	bson_destroy(update);
	return createReturnObject(RT_RETURN, createBooleanValueObject(result));

}

ReturnObject *updateManyWrapper(struct scopeobject *scope)
{
	return NULL;
}

ReturnObject *removeOneWrapper(struct scopeobject *scope)
{
	return NULL;
}

ReturnObject *removeManyWrapper(struct scopeobject *scope)
{
	return NULL;
}

ReturnObject *mdbconnectWrapper(struct scopeobject *scope)
{
	ValueObject *url = getArg(scope, "url");
	if (url->type != VT_STRING) {
		fprintf(stderr, "mongodb: url must be string\n");
		return NULL;
	}
	mongoc_client_t *client = mongoc_client_new(getString(url));
	if (!client) {
		fprintf(stderr, "mongodb: failed to connect to database\n");
		return NULL;
	}
	ValueObject *ret = createBlobValueObject(client);
	if (!ret) {
		fprintf(stderr, "mongodb: failed to create client\n");
		mongoc_client_destroy(client);
		return NULL;
	}
	ret->dtor = (void (*)(void*))mongoc_client_destroy;
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *getCollectionWrapper(struct scopeobject *scope)
{
	ValueObject *clientObject = getArg(scope, "client");
	if (clientObject->type != VT_BLOB) {
		fprintf(stderr, "mongodb: client object must be blob object\n");
		return NULL;
	}
	mongoc_client_t *client = (mongoc_client_t *)getBlob(clientObject);
	ValueObject *db = getArg(scope, "db");
	ValueObject *collName = getArg(scope, "coll");
	if (db->type != VT_STRING && collName->type != VT_STRING) {
		fprintf(stderr, "mongodb: coll and db\n");
		return NULL;
	}
	mongoc_collection_t *coll = mongoc_client_get_collection(client,
								 getString(db),
								 getString(collName));
	if (!coll) {
		fprintf(stderr, "mongodb: failed to get collection %s.%s\n", getString(db), getString(collName));
		return NULL;
	}
	ValueObject *ret = createBlobValueObject(coll);
	if (!ret) {
		fprintf(stderr, "mongodb: failed to get collection\n");
		mongoc_collection_destroy(coll);
		return NULL;
	}
	ret->dtor = (void (*)(void *))mongoc_collection_destroy;
	return createReturnObject(RT_RETURN, ret);
}

ReturnObject *pbjson(struct scopeobject *scope)
{
	ValueObject *thingO = getArg(scope, "thing");
	ScopeObject *thing = getArray(thingO);
	bson_t *bson = scope2bson(thing);
	size_t len = 0;
	char * json = bson_as_json(bson, &len);
	printf("%.*s\n", (int)len, json);
	bson_free(bson);
	return createReturnObject(RT_DEFAULT, NULL);
}

ReturnObject *getField(struct scopeobject *scope)
{
	ValueObject *nameO = getArg(scope, "name");
	if (nameO->type != VT_STRING) {
		fprintf(stderr, "getField name should be string\n");
		return NULL;
	}
	char *name = getString(nameO);
	ValueObject *formO = getArg(scope, "form");
	if (formO->type != VT_STRING) {
		fprintf(stderr, "getField form should be string\n");
		return NULL;
	}
	char *form = getString(formO);
	int i = 0;
	int namei = 0;
	int namelen = strlen(name);
	int formlen = strlen(form);
	int matching = 1;
	int found = 0;
	while (i < formlen) {
		if (matching) {
			
			if (form[i] == name[namei]) {
				namei++;
			}
				
			if (i + 1 < formlen && form[i + 1] == '=') {
				if (namei == namelen) {
					i += 2;
					found = 1;
					break;
				} else {
					matching = 0;
					namei = 0;
				}
			}
		} else {
			if (form[i] == '&') {
				matching = 1;
				namei = 0;
			}
		}
		i++;
	}
	if (!found) return createReturnObject(RT_RETURN, createNilValueObject());
	int end = i;
	for (end = 0; end < formlen; end++) {
		if (form[end] == '&') break;
	}
	char *new = malloc(sizeof(char) * (end - i) + 1);
	for (namei = 0; namei < end - i; namei++) {
		if (form[namei + i] == '+') {
			new[namei] = ' ';
		} else {
			new[namei] = form[namei + i];
		}
	}
	new[end - i] = '\0';
	return createReturnObject(RT_RETURN, createStringValueObject(new));
}

void loadLibrary(ScopeObject *scope, IdentifierNode *target)
{
	char *name = NULL;
	int status;
	ScopeObject *lib = NULL;
	IdentifierNode *id = NULL;
	ValueObject *val = NULL;
	if (target == NULL) return;

	name = resolveIdentifierName(target, scope);
	if (!name) goto loadLibraryAbort;

	if (!strcmp(name, "STDLIB")) {
		lib = createScopeObject(scope);
		if (!lib) goto loadLibraryAbort;

		loadBinding(lib, "MIX", "seed", &srandWrapper);
		loadBinding(lib, "BLOW", "max", &randWrapper);

		id = createIdentifierNode(IT_DIRECT, (void *)copyString("STDLIB"), NULL, NULL, 0);
		if (!id) goto loadLibraryAbort;

		if (!createScopeValue(scope, scope, id)) goto loadLibraryAbort;

		val = createArrayValueObject(lib);
		if (!val) goto loadLibraryAbort;
		lib = NULL;

		if (!updateScopeValue(scope, scope, id, val)) goto loadLibraryAbort;
		deleteIdentifierNode(id);
	} else if (!strcmp(name, "STDIO")) {
		lib = createScopeObject(scope);
		if (!lib) goto loadLibraryAbort;

		loadBinding(lib, "OPEN", "filename mode", &fopenWrapper);
		loadBinding(lib, "DIAF", "file", &ferrorWrapper);
		loadBinding(lib, "LUK", "file length", &freadWrapper);
		loadBinding(lib, "SCRIBBEL", "file data", &fwriteWrapper);
		loadBinding(lib, "AGEIN", "file", &rewindWrapper);
		loadBinding(lib, "CLOSE", "file", &fcloseWrapper);

		id = createIdentifierNode(IT_DIRECT, (void *)copyString("STDIO"), NULL, NULL, 0);
		if (!id) goto loadLibraryAbort;

		if (!createScopeValue(scope, scope, id)) goto loadLibraryAbort;

		val = createArrayValueObject(lib);
		if (!val) goto loadLibraryAbort;
		lib = NULL;

		if (!updateScopeValue(scope, scope, id, val)) goto loadLibraryAbort;
		deleteIdentifierNode(id);
	} else if (!strcmp(name, "SOCKS")) {
		lib = createScopeObject(scope);
		if (!lib) goto loadLibraryAbort;

		loadBinding(lib, "RESOLV", "addr", &ilookupWrapper);
		loadBinding(lib, "BIND", "addr port", &iopenWrapper);
		loadBinding(lib, "LISTN", "local", &iacceptWrapper);
		loadBinding(lib, "KONN", "local addr port", &iconnectWrapper);
		loadBinding(lib, "CLOSE", "local", &icloseWrapper);
		loadBinding(lib, "PUT", "local remote data", &isendWrapper);
		loadBinding(lib, "GET", "local remote amount", &ireceiveWrapper);

		id = createIdentifierNode(IT_DIRECT, (void *)copyString("SOCKS"), NULL, NULL, 0);
		if (!id) goto loadLibraryAbort;

		if (!createScopeValue(scope, scope, id)) goto loadLibraryAbort;

		val = createArrayValueObject(lib);
		if (!val) goto loadLibraryAbort;
		lib = NULL;

		if (!updateScopeValue(scope, scope, id, val)) goto loadLibraryAbort;
		deleteIdentifierNode(id);
	} else if (!strcmp(name, "STRING")) {
		lib = createScopeObject(scope);
		if (!lib) goto loadLibraryAbort;

		loadBinding(lib, "LEN", "string", &strlenWrapper);
		loadBinding(lib, "AT", "string position", &stratWrapper);

		id = createIdentifierNode(IT_DIRECT, (void *)copyString("STRING"), NULL, NULL, 0);
		if (!id) goto loadLibraryAbort;

		if (!createScopeValue(scope, scope, id)) goto loadLibraryAbort;

		val = createArrayValueObject(lib);
		if (!val) goto loadLibraryAbort;
		lib = NULL;

		if (!updateScopeValue(scope, scope, id, val)) goto loadLibraryAbort;
		deleteIdentifierNode(id);
	} else if (!strcmp(name, "MANGO")) {
		mongoc_init();
		lib = createScopeObject(scope);
		if (!lib) goto loadLibraryAbort;

		loadBinding(lib, "INSERTIN", "coll doc", &insertOneWrapper);
		loadBinding(lib, "INSERTIN_SUM", "coll docs", &insertManyWrapper);
		loadBinding(lib, "FINDIN", "coll query", &findWrapper);
		loadBinding(lib, "UPDOOTIN", "coll query update", &updateOneWrapper);
		loadBinding(lib, "UPDATEMANY", "update many", &updateManyWrapper);
		loadBinding(lib, "REMOVEONE", "remove one", &removeOneWrapper);
		loadBinding(lib, "REMOVEMANY", "remove many", &removeManyWrapper);
		loadBinding(lib, "CONNEKTIN", "url", &mdbconnectWrapper);
		loadBinding(lib, "COLEKTIN", "client db coll", &getCollectionWrapper);
		loadBinding(lib, "PBJSON", "thing", &pbjson);
		loadBinding(lib, "PARSIN", "name form", &getField);
		
		

		id = CPYKEY("MANGO");
		if (!id) goto loadLibraryAbort;

		if (!createScopeValue(scope, scope, id)) goto loadLibraryAbort;

		val = createArrayValueObject(lib);
		if (!val) goto loadLibraryAbort;
		lib = NULL;

		if (!updateScopeValue(scope, scope, id, val)) goto loadLibraryAbort;
		deleteIdentifierNode(id);
	}

	if (name) free(name);
	return;

loadLibraryAbort: /* In case something goes wrong... */

	/* Clean up any allocated structures */
	if (name) free(name);
	if (lib) deleteScopeObject(lib);
	if (id) deleteIdentifierNode(id);
	if (val) deleteValueObject(val);
	return;
}

void loadBinding(ScopeObject *scope, char *name, const char *args, struct returnobject *(*binding)(struct scopeobject *))
{
	IdentifierNode *id = NULL;
	StmtNodeList *stmts = NULL;
	BindingStmtNode *stmt = NULL;
	StmtNode *wrapper = NULL;
	int status;
	BlockNode *body = NULL;
	IdentifierNodeList *ids = NULL;
	IdentifierNode *arg = NULL;
	if (name == NULL || binding == NULL) return;

	id = createIdentifierNode(IT_DIRECT, (void *)copyString(name), NULL, NULL, 0);
	if (!id) goto loadBindingAbort;

	stmts = createStmtNodeList();
	if (!stmts) goto loadBindingAbort;

	stmt = createBindingStmtNode(binding);
	if (!stmt) goto loadBindingAbort;

	wrapper = createStmtNode(ST_BINDING, stmt);
	if (!wrapper) goto loadBindingAbort;
	stmt = NULL;

	status = addStmtNode(stmts, wrapper);
	if (!status) goto loadBindingAbort;
	wrapper = NULL;

	body = createBlockNode(stmts);
	if (!body) goto loadBindingAbort;
	stmts = NULL;

	ids = createIdentifierNodeList();
	if (!ids) goto loadBindingAbort;

	const char *start = args;
	while (start != NULL) {
		char *end = strchr(start, ' ');
		char *temp = NULL;
		unsigned int len = 0;

		if (end != NULL) len = (end - start);
		else len = strlen(start);

		temp = malloc(sizeof(char) * (len + 1));
		strncpy(temp, start, len);
		temp[len] = '\0';

		if (end != NULL) start = (end + 1);
		else start = NULL;

		arg = createIdentifierNode(IT_DIRECT, (void *)temp, NULL, NULL, 0);
		if (!arg) goto loadBindingAbort;

		status = addIdentifierNode(ids, arg);
		if (!status) goto loadBindingAbort;
	}

	FuncDefStmtNode *interface = createFuncDefStmtNode(NULL, id, ids, body);
	if (!interface) goto loadBindingAbort;

	ValueObject *val = createFunctionValueObject(interface);
	if (!val) goto loadBindingAbort;

	createScopeValue(scope, scope, id);
	updateScopeValue(scope, scope, id, val);

	return;

loadBindingAbort: /* In case something goes wrong... */

	if (id) deleteIdentifierNode(id);
	if (val) deleteValueObject(val);
	else if (interface) deleteFuncDefStmtNode(interface);
	else {
		if (arg) deleteIdentifierNode(arg);
		if (ids) deleteIdentifierNodeList(ids);
		if (body) deleteBlockNode(body);
		if (stmts) deleteStmtNodeList(stmts);
		if (wrapper) deleteStmtNode(wrapper);
		if (stmt) deleteBindingStmtNode(stmt);
	}
	return;
}
