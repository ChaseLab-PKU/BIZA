#include "dm-biza.h"

static inline bool biza_heap_is_empty(struct biza_heap *queue)
{
	return queue->size == 0;
}

static inline bool biza_heap_is_full(struct biza_heap *queue)
{
	return queue->size == queue->capacity;
}

static inline void biza_heap_entry_swap(struct biza_heap_entry **a, struct biza_heap_entry **b)
{
    struct biza_heap_entry *temp = *a;
    *a = *b;
    *b = temp;
}

static void heapifyUp(struct biza_heap *queue, int index)
{
	int parent = (index - 1) / 2;
	while (index > 0 && queue->elements[index]->priority > queue->elements[parent]->priority) {
		biza_heap_entry_swap(&queue->elements[index], &queue->elements[parent]);
		index = parent;
		parent = (index - 1) / 2;
	}
}

static void heapifyDown(struct biza_heap *queue, int index)
{
	int left = 2 * index + 1;
	int right = 2 * index + 2;
	int largest = index;

	if (left < queue->size && queue->elements[left]->priority > queue->elements[largest]->priority) {
		largest = left;
	}

	if (right < queue->size && queue->elements[right]->priority > queue->elements[largest]->priority) {
		largest = right;
	}

	if (largest != index) {
		biza_heap_entry_swap(&queue->elements[index], &queue->elements[largest]);
		heapifyDown(queue, largest);
	}
}

static struct biza_heap_entry *biza_heap_dequeue(struct biza_heap *queue)
{   
    struct biza_heap_entry *element;

    if (biza_heap_is_empty(queue))
	    return NULL;

    element = queue->elements[0];

    queue->elements[0] = queue->elements[queue->size - 1];
    queue->size--;

    heapifyDown(queue, 0);

    return element;
}

static struct biza_heap_entry *biza_heap_get_max(struct biza_heap *queue)
{   
    struct biza_heap_entry *element;

    if (biza_heap_is_empty(queue))
	    return NULL;

    element = queue->elements[0];

    return element;
}

static void biza_heap_enqueue(struct biza_heap *queue, struct biza_heap_entry *element)
{   
    BUG_ON(biza_heap_is_full(queue));

	queue->elements[queue->size] = element;
	queue->size++;

	heapifyUp(queue, queue->size - 1);
}

static void biza_heap_update(struct biza_heap *queue, int key, int newPriority)
{
    int org;
	int index = -1;
    int i;

	for (i = 0; i < queue->size; i++) {
		if (queue->elements[i]->key == key) {
			index = i;
			break;
		}
	}

	if (index == -1) return;

    org = queue->elements[index]->priority;
	queue->elements[index]->priority = newPriority;

	if (newPriority > org) {
		heapifyUp(queue, index);
	} else {
		heapifyDown(queue, index);
	}
}

static void biza_heap_delete(struct biza_heap *queue, int key)
{
	int index = -1;
	int i;

	for (i = 0; i < queue->size; i++) {
		if (queue->elements[i]->key == key) {
			index = i;
			break;
		}
	}

	if (index == -1)
		return;
    
    kfree(queue->elements[index]);
	queue->elements[index] = queue->elements[queue->size - 1];
    queue->elements[queue->size - 1] = NULL;
	queue->size--;

	heapifyDown(queue, index);
}

static struct biza_heap* biza_heap_create(int capacity)
{
	struct biza_heap *heap = kzalloc(sizeof(struct biza_heap), GFP_KERNEL);
	heap->elements = kzalloc(capacity * sizeof(struct biza_heap_entry *), GFP_KERNEL);
	heap->size = 0;
	heap->capacity = capacity;
	return heap;
}

static void biza_heap_destroy(struct biza_heap* heap)
{
    struct biza_heap_entry *del_etr;

    del_etr = biza_heap_dequeue(heap);
    while(del_etr) {
        kfree(del_etr);
	del_etr = biza_heap_dequeue(heap);
    }

    kfree(heap->elements);
    heap->size = 0;
}

static void printHeap(struct biza_heap *queue)
{   
    int i;

	pr_err("Priority Queue:\n");
	for (i = 0; i < queue->size; i++) {
		pr_err("(%d, %d) ", queue->elements[i]->key, queue->elements[i]->priority);
	}
	pr_err("\n");
}


int biza_ctr_pred(struct biza_target *bt)
{
    int ret;
    
    bt->lru = kzalloc(sizeof(struct biza_lru), GFP_KERNEL);
    if(!bt->lru) {
        pr_err("dm-biza: Cannot alloc lru\n");
        ret = -ENOMEM;
        goto err;
    }
    INIT_LIST_HEAD(&bt->lru->list);
    hash_init(bt->htable);
    bt->lru->size = 0;

    bt->heap_cnt = biza_heap_create(BIZA_LIFETIME_AWARE_SET_CAPACITY);
    if(!bt->heap_cnt) {
        pr_err("dm-biza: Cannot alloc heap_cnt\n");
        ret = -ENOMEM;
        goto err_lru;
    }
    bt->max_dist_lfta_set = 0;
    bt->min_dist_lfta_set = INT_MAX;

    bt->heap_dist = biza_heap_create(BIZA_ZRWA_AWARE_SET_CAPACITY);
    if(!bt->heap_dist) {
        pr_err("dm-biza: Cannot alloc heap_dist\n");
        ret = -ENOMEM;
        goto err_cnt;
    }

    return 0;

err_cnt:
    biza_heap_destroy(bt->heap_cnt);
err_lru:
    kfree(bt->lru);
err:
    return ret;
}

void biza_dtr_pred(struct biza_target *bt)
{   
    biza_heap_destroy(bt->heap_dist);
    biza_heap_destroy(bt->heap_cnt);
    kfree(bt->lru);
}



inline static struct biza_htable_entry * biza_htable_find(struct biza_target *bt, sector_t key)
{
    struct biza_htable_entry *tb_etr;

    hash_for_each_possible(bt->htable, tb_etr, link, key) {
        if(tb_etr->lcn == key) return tb_etr;
    }

    return NULL;
}


inline static void biza_update_reuse_dist(struct biza_target *bt, struct biza_pred_entry *etr, uint32_t new_dist)
{   
    etr->reuse_dist = new_dist;
    if(etr->aware_type == BIZA_ZRWA_AWARE) {
        biza_heap_update(bt->heap_dist, etr->lcn, new_dist);
    }
    else if(etr->aware_type == BIZA_LIFETIME_AWARE) {
        if(etr->reuse_dist > bt->max_dist_lfta_set) bt->max_dist_lfta_set = etr->reuse_dist;
        if(etr->reuse_dist < bt->min_dist_lfta_set) bt->min_dist_lfta_set = etr->reuse_dist;
    }
}


inline static void biza_update_reuse_cnt(struct biza_target *bt, struct biza_pred_entry *etr, uint32_t new_cnt)
{   
    etr->reuse_cnt = new_cnt;

    if(etr->aware_type == BIZA_ZRWA_AWARE || etr->aware_type == BIZA_LIFETIME_AWARE) {
        biza_heap_update(bt->heap_cnt, etr->lcn, -new_cnt);
    }
}


// Can the pred_etr be write in zrwa aware zones?
inline static bool biza_can_insert_zrwa_aware_set(struct biza_target *bt, struct biza_pred_entry *pred_etr)
{
    struct biza_heap_entry *n = NULL;
    uint32_t threshold;

    if(pred_etr->aware_type != BIZA_LIFETIME_AWARE) return false;
    if(pred_etr->reuse_dist > BIZA_ZRWA_AWARE_REUSE_DIST_THRESHOLD) return false;
    if(!biza_heap_is_full(bt->heap_dist)) return true;

    n = biza_heap_get_max(bt->heap_dist);
    BUG_ON(!n);

    threshold = n->pred_entry->reuse_dist;

    BUG_ON(n->priority != n->pred_entry->reuse_dist);

    return pred_etr->reuse_dist < threshold;
}

// zrwa aware set evice
inline static void biza_evict_zrwa_aware_set(struct biza_target *bt)
{
	struct biza_heap_entry *del_heap_etr = NULL;
	struct biza_pred_entry *del_pred_etr = NULL;

    del_heap_etr = biza_heap_dequeue(bt->heap_dist);
	BUG_ON(!del_heap_etr);
	del_pred_etr = del_heap_etr->pred_entry;
    kfree(del_heap_etr);

	del_pred_etr->aware_type = BIZA_LIFETIME_AWARE;
}

// zrwa aware set insert
static void biza_insert_zrwa_aware_set(struct biza_target *bt, struct biza_pred_entry *new_etr)
{   
    struct biza_heap_entry *new_heap_etr = kzalloc(sizeof(struct biza_heap_entry), GFP_KERNEL);

    if(biza_heap_is_full(bt->heap_dist)) biza_evict_zrwa_aware_set(bt); 

    new_heap_etr->key = new_etr->lcn;
    new_heap_etr->pred_entry = new_etr;
    new_heap_etr->priority = new_etr->reuse_dist;

    new_etr->aware_type = BIZA_ZRWA_AWARE;

    biza_heap_enqueue(bt->heap_dist, new_heap_etr);
}

// Can the pred_etr be write in lifetime aware zones?
inline static bool biza_can_insert_lifetime_aware_set(struct biza_target *bt, struct biza_pred_entry *pred_etr)
{   
    struct biza_heap_entry *n = NULL;
    uint32_t threshold;
    
    BUG_ON(BIZA_LIFETIME_AWARE_REUSE_CNT_THRESHOLD == 0);

    if(pred_etr->aware_type != BIZA_TRIVIAL) return false;
    if(pred_etr->reuse_cnt < BIZA_LIFETIME_AWARE_REUSE_CNT_THRESHOLD) return false;
    if (!biza_heap_is_full(bt->heap_cnt)) return true;


    n = biza_heap_get_max(bt->heap_cnt);
    BUG_ON(!n);

    threshold = n->pred_entry->reuse_cnt;

    BUG_ON(n->priority != -n->pred_entry->reuse_cnt);

    return pred_etr->reuse_cnt > threshold;
}

// lifetime aware set evict
inline static void biza_evict_lifetime_aware_set(struct biza_target *bt)
{   
    struct biza_heap_entry *del_heap_etr = NULL;
	struct biza_pred_entry *del_pred_etr = NULL;

    del_heap_etr = biza_heap_dequeue(bt->heap_cnt);
	BUG_ON(!del_heap_etr);
	del_pred_etr = del_heap_etr->pred_entry;

	BUG_ON(del_pred_etr->aware_type != BIZA_ZRWA_AWARE && del_pred_etr->aware_type != BIZA_LIFETIME_AWARE);

	if (del_pred_etr->aware_type == BIZA_ZRWA_AWARE) {
        biza_heap_delete(bt->heap_dist, del_pred_etr->lcn);
	}
    kfree(del_heap_etr);

    del_pred_etr->aware_type = BIZA_TRIVIAL;
}

// lifetime aware set insert
static void biza_insert_lifetime_aware_set(struct biza_target *bt, struct biza_pred_entry *new_etr)
{
    struct biza_heap_entry *new_heap_etr = kzalloc(sizeof(struct biza_heap_entry), GFP_KERNEL);

    if(biza_heap_is_full(bt->heap_cnt)) biza_evict_lifetime_aware_set(bt);

    new_heap_etr->key = new_etr->lcn;
    new_heap_etr->pred_entry = new_etr;
    new_heap_etr->priority = -new_etr->reuse_cnt;

    new_etr->aware_type = BIZA_LIFETIME_AWARE;

    biza_heap_enqueue(bt->heap_cnt, new_heap_etr);
}

// predition set evict 
static void biza_evict_pred_set(struct biza_target *bt)
{   
    struct biza_pred_entry *del_pred_etr = NULL;
    struct biza_htable_entry *del_tb_etr = NULL;
    
    while(true) {
        del_pred_etr = list_first_entry(&bt->lru->list, struct biza_pred_entry, lru_link);
        if(del_pred_etr->reuse_cnt >= 2) {
            list_del(&del_pred_etr->lru_link);
            biza_update_reuse_cnt(bt, del_pred_etr, del_pred_etr->reuse_cnt-2);
            list_add_tail(&del_pred_etr->lru_link, &bt->lru->list);
        }
        else break;
    }

    switch (del_pred_etr->aware_type) {
    case BIZA_ZRWA_AWARE:
        biza_heap_delete(bt->heap_dist, del_pred_etr->lcn);
    case BIZA_LIFETIME_AWARE:
        biza_heap_delete(bt->heap_cnt, del_pred_etr->lcn);
    case BIZA_TRIVIAL:
        list_del(&del_pred_etr->lru_link);
        bt->lru->size--;
        break;
    default:
        BUG_ON(1);
    }
    kfree(del_pred_etr);

    /** delete in hash table **/
    del_tb_etr = biza_htable_find(bt, del_pred_etr->lcn);
    hash_del(&del_tb_etr->link);
    kfree(del_tb_etr);
}


// predition set insert 
static void biza_insert_pred_set(struct biza_target *bt, sector_t lcn)
{   
    struct biza_pred_entry *pred_etr = NULL;
    struct biza_htable_entry *tb_etr = NULL;

    if(bt->lru->size >= BIZA_PRED_SET_CAPACITY) biza_evict_pred_set(bt);

    pred_etr = kzalloc(sizeof(struct biza_pred_entry), GFP_KERNEL);
    BUG_ON(!pred_etr);
    pred_etr->lcn = lcn;
    pred_etr->reuse_cnt = 0;
    pred_etr->reuse_dist = INT_MAX;
    pred_etr->last_wrt_time = bt->wrt_time;
    pred_etr->aware_type = BIZA_TRIVIAL;
    list_add_tail(&pred_etr->lru_link, &bt->lru->list);
    bt->lru->size++;

    tb_etr = kzalloc(sizeof(struct biza_htable_entry), GFP_KERNEL);
    BUG_ON(!tb_etr);
    tb_etr->lcn = lcn;
    tb_etr->pred_entry = pred_etr;
    hash_add(bt->htable, &tb_etr->link, lcn);
}

inline static void biza_update_entry(struct biza_target *bt, struct biza_pred_entry *pred_etr, sector_t lcn)
{
    biza_update_reuse_cnt(bt, pred_etr, pred_etr->reuse_cnt+1);
    biza_update_reuse_dist(bt, pred_etr, bt->wrt_time - pred_etr->last_wrt_time);
    pred_etr->last_wrt_time = bt->wrt_time;

    list_del(&pred_etr->lru_link);
    list_add_tail(&pred_etr->lru_link, &bt->lru->list);
}

inline static void biza_promote_entry(struct biza_target *bt, struct biza_pred_entry *pred_etr)
{
    if(biza_can_insert_lifetime_aware_set(bt, pred_etr)) {
        biza_insert_lifetime_aware_set(bt, pred_etr);
    }

    if(biza_can_insert_zrwa_aware_set(bt, pred_etr)) {
        biza_insert_zrwa_aware_set(bt, pred_etr);
    }
}



// Update LRU in every write
void biza_update_pred(struct biza_target *bt, sector_t lcn)
{   
    struct biza_htable_entry *tb_etr = NULL;
    struct biza_pred_entry *pred_etr = NULL;

    mutex_lock(&bt->pred_lock);
    bt->wrt_time++;

    tb_etr = biza_htable_find(bt, lcn);
    if(!tb_etr) biza_insert_pred_set(bt, lcn);
    else {   // Already in LRU
        pred_etr = tb_etr->pred_entry;
        biza_update_entry(bt, tb_etr->pred_entry, lcn);
        biza_promote_entry(bt, pred_etr);
    }
    mutex_unlock(&bt->pred_lock);
}



/**
 * Choose a open zone, return its open zone idx (instead of zone idx)
 */
uint8_t biza_choose_open_zone_to_write(struct biza_target *bt, uint8_t drive_idx, uint32_t hint)
{   
    struct biza_htable_entry *tb_etr = NULL;
    struct biza_pred_entry *pred_etr = NULL;
    struct biza_dev *dev = &bt->devs[drive_idx];
    uint32_t interval;
    uint8_t ozg_idx, oz_idx;

    mutex_lock(&bt->pred_lock);
    tb_etr = biza_htable_find(bt, hint);
    pred_etr = tb_etr->pred_entry;

    switch (pred_etr->aware_type) {
    case BIZA_ZRWA_AWARE:
        ozg_idx = (get_random_u32() % dev->nr_zrwa_aware_open_zones) / BIZA_NR_ISOLATION_DOMAIN;
        oz_idx = biza_get_oz_idx_gc_avoid(bt, dev, ozg_idx);
        break;
    case BIZA_LIFETIME_AWARE:
        if(bt->max_dist_lfta_set < bt->min_dist_lfta_set) {
            ozg_idx = (dev->nr_zrwa_aware_open_zones + get_random_u32() % dev->nr_lifetime_aware_open_zones) 
                    / BIZA_NR_ISOLATION_DOMAIN;
            oz_idx = biza_get_oz_idx_gc_avoid(bt, dev, ozg_idx);
        }
        else {
            interval = (bt->max_dist_lfta_set - bt->min_dist_lfta_set) 
                     / (dev->nr_lifetime_aware_open_zones / BIZA_NR_ISOLATION_DOMAIN);
            if(interval == 0) {
                ozg_idx = (dev->nr_zrwa_aware_open_zones + get_random_u32() % dev->nr_lifetime_aware_open_zones) 
                        / BIZA_NR_ISOLATION_DOMAIN;
            }
            else {
                ozg_idx = (dev->nr_zrwa_aware_open_zones / BIZA_NR_ISOLATION_DOMAIN)
                         + (pred_etr->reuse_dist - bt->min_dist_lfta_set) / interval;
                ozg_idx = min(ozg_idx, (uint8_t)((dev->nr_zrwa_aware_open_zones + dev->nr_lifetime_aware_open_zones)
                                                 / BIZA_NR_ISOLATION_DOMAIN));
            }
            oz_idx = biza_get_oz_idx_gc_avoid(bt, dev, ozg_idx);
        }
        break;
    case BIZA_TRIVIAL:
        ozg_idx = (dev->nr_zrwa_aware_open_zones + dev->nr_lifetime_aware_open_zones + get_random_u32() % dev->nr_trivial_open_zones)
                / BIZA_NR_ISOLATION_DOMAIN;
        oz_idx = biza_get_oz_idx_gc_avoid(bt, dev, ozg_idx);
        break;
    default:
        BUG_ON(1);
    }
    mutex_unlock(&bt->pred_lock);

    return oz_idx;
}

