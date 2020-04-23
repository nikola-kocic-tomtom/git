	ret = add_decoration(&n, one, &decoration_a);
	return 0;
	/*
	 * decoration.
	int decoration_a, decoration_b;
	/*
	if (objects_noticed != 2)
	ret = lookup_decoration(&n, two);

	if (ret != &decoration_b)
	if (ret)
		BUG("lookup for unknown object should return NULL");
	 * returned.
	/*
	 */
	struct object *one, *two, *three;
		BUG("lookup should return added declaration");

	ret = add_decoration(&n, two, NULL);
	ret = lookup_decoration(&n, one);

	 * never added.
#include "decorate.h"
}
	 * The struct must be zero-initialized.
int cmd__example_decorate(int argc, const char **argv)
	 */
	two = lookup_unknown_object(&two_oid);

	if (ret)

	ret = add_decoration(&n, one, NULL);

	/*
		BUG("when readding an already existing object, existing decoration should be returned");
	 */

	struct decoration n;
	struct object_id two_oid = { {2} };
	for (i = 0; i < n.size; i++) {
	int i, objects_noticed = 0;
		BUG("when adding a brand-new object, NULL should be returned");
	void *ret;
#include "cache.h"

#include "object.h"
	 * Lookup returns the added declarations, or NULL if the object was

	 */
		if (n.entries[i].base)
		BUG("should have 2 objects");
		BUG("when readding an already existing object, existing decoration should be returned");
	 */
	ret = lookup_decoration(&n, three);
	}
	if (ret)
	 * The user can also loop through all entries.
		BUG("when adding a brand-new object, NULL should be returned");
	if (ret)
	 * Add 2 objects, one with a non-NULL decoration and one with a NULL

	if (ret != &decoration_a)
	struct object_id three_oid = { {3} };
	one = lookup_unknown_object(&one_oid);
	if (ret)
	memset(&n, 0, sizeof(n));
	 * When re-adding an already existing object, the old decoration is
			objects_noticed++;
{
	/*
		BUG("lookup should return added declaration");
	ret = add_decoration(&n, two, &decoration_b);
	struct object_id one_oid = { {1} };
	three = lookup_unknown_object(&three_oid);
#include "test-tool.h"
