#include "dm-biza.h"

/**
 * When open a zone, predict which isolation domain (i.e., I/O channel) it map with.
 * in a round-robin manner
 */
static inline uint8_t biza_predict_isolation_domain(struct biza_target *bt, struct biza_dev *dev)
{
    return atomic_inc_return(&dev->open_zone_cnt) % bt->params->nr_isolation_domains;
}

// open an empty zone with zrwa
// return opend zone idx, idx = dev->nr_zones means no empty zone or open error
/** WARN: This function is real malicious now **/ 
/** WARN: Move it to blk layer or nvme driver will be better **/ 
uint32_t biza_open_empty_zone(struct biza_target *bt, struct biza_dev *dev, bool zrwa, biza_aware_type type) 
{   
    struct gendisk *disk = dev->dev->bdev->bd_disk;
    struct nvme_passthru_cmd cmd = {};
    uint32_t i;
    int err;
    
    for (i = 0; i < dev->nr_zones; ++i) {
        if (dev->zones[i].cond == BLK_ZONE_COND_EMPTY) {
            cmd.opcode = nvme_cmd_zone_mgmt_send;
            cmd.cdw10 = (dev->zones[i].start >> PAGE_SECTORS_SHIFT) & 0xffffffff;
            cmd.cdw11 = (dev->zones[i].start >> PAGE_SECTORS_SHIFT) >> 32;
            cmd.cdw13 = (0x3 & 0xff) | ((zrwa? 0x1:0x0) << 9);  // refer to NVMe specification
            cmd.nsid = dev->ns_id;

            // i.e., nvme_ioctl
            err = disk->fops->ioctl(dev->dev->bdev, 0, NVME_IOCTL_IO_CMD, (unsigned long)&cmd);
            if (err) {
                pr_err("dm-biza: open zone error: dev: %s, zone_idx %d\n",  disk->disk_name, i);
                return dev->nr_zones;
            }

            dev->zones[i].cond = BLK_ZONE_COND_EXP_OPEN;
            dev->zones[i].nr_invalid_chunks = 0;

            dev->zones[i].zrwa_wd = kzalloc(BITS_TO_BYTES(dev->zrwa_size_chunk), GFP_KERNEL);
            if(!dev->zones[i].zrwa_wd) {
                pr_err("dm-biza: open zone error: cannot alloc zrwa window bitmap for zone_idx %d\n", i);
                return dev->nr_zones;
            }
            atomic_set(&dev->zones[i].debug_cnt, 0);

            dev->zones[i].aware_type = type;
            dev->zones[i].iso_dm = biza_predict_isolation_domain(bt, dev);
            dev->zones[i].iso_dm_conf = BIZA_ISO_DOMAIN_CONFIDENCE;
            dev->zones[i].iso_dm_vote = 0;
            dev->zones[i].high_lat_score = 0;
            
            bt->gc->nr_free_zones--;
            bt->gc->p_free_zones = bt->gc->nr_free_zones * 100 / (bt->params->nr_zones_per_drive * bt->params->nr_drives);

            break;
        }
    }

    return i;
}  

// Finish a zone and release the zrwa resources
static int biza_finish_zone(struct biza_target *bt, struct biza_dev *dev, uint32_t zone_idx)
{
    int ret;

    dev->zones[zone_idx].wp = dev->zones[zone_idx].start + dev->zones[zone_idx].capacity;
    ret = blkdev_zone_mgmt(dev->dev->bdev, REQ_OP_ZONE_FINISH, dev->zones[zone_idx].start,
                   dev->zones[zone_idx].len, GFP_NOIO);

    return ret;
}

// Reset a zone or all zone
int biza_reset_zone(struct biza_target *bt, struct biza_dev *dev, uint32_t zone_idx, bool all)
{
    int i = 0, ret = 0;
    
    if (all) {
        for(i = 0; i < dev->nr_zones; ++i) {
            dev->zones[i].wp = dev->zones[i].start;
            // atomic64_set(&dev->zones[i].wp, dev->zones[i].start);
            dev->zones[i].cond = BLK_ZONE_COND_EMPTY;
            dev->zones[i].nr_invalid_chunks = 0;
        }
        for(i = 0; i < dev->nr_zrwa_aware_open_zones + dev->nr_lifetime_aware_open_zones + dev->nr_trivial_open_zones; ++i) {
            zone_idx = dev->open_zones[i];
            if(dev->zones[zone_idx].zrwa_wd) {
                kfree(dev->zones[zone_idx].zrwa_wd);
                dev->zones[zone_idx].zrwa_wd = NULL;
            }
        }
        bt->gc->nr_free_zones = bt->params->nr_zones_per_drive * bt->params->nr_drives;
        bt->gc->p_free_zones = 100;
        ret = blkdev_zone_mgmt(dev->dev->bdev, REQ_OP_ZONE_RESET, 0,dev->len, GFP_NOIO);
    }
    else {
        dev->zones[zone_idx].wp = dev->zones[zone_idx].start;
        // atomic64_set(&dev->zones[i].wp, dev->zones[zone_idx].start);
        dev->zones[zone_idx].cond = BLK_ZONE_COND_EMPTY;
        dev->zones[zone_idx].nr_invalid_chunks = 0;
        if(dev->zones[zone_idx].zrwa_wd) {
            kfree(dev->zones[zone_idx].zrwa_wd);
            dev->zones[zone_idx].zrwa_wd = NULL;
        }
        bt->gc->nr_free_zones++;
        bt->gc->p_free_zones = bt->gc->nr_free_zones * 100 / (bt->params->nr_zones_per_drive * bt->params->nr_drives);
        ret = blkdev_zone_mgmt(dev->dev->bdev, REQ_OP_ZONE_RESET, dev->zones[zone_idx].start,
                   dev->zones[zone_idx].len, GFP_NOIO);
    }

    BUG_ON(ret);
    
    return ret;
}


// Initialize a zone
static int biza_init_zone(struct blk_zone *blkz, unsigned int idx, void *data)
{   
    struct biza_dev *dev = data;
	struct biza_zone *zone = &dev->zones[idx];

    BUG_ON(blkz->cond == BLK_ZONE_COND_NOT_WP);
    zone->cond = blkz->cond;

    zone->wp = blkz->wp;
    // atomic64_set(&zone->wp, blkz->wp);
    zone->start = blkz->start;
    zone->capacity = blkz->capacity;
    zone->len = blkz->len;
    zone->nr_invalid_chunks = 0;

    dev->capacity += zone->capacity;
    dev->len += zone->len;

    spin_lock_init(&zone->zlock);

    return 0;
}


// Free devs
static inline void biza_free_devs(struct biza_target *bt, uint8_t cnt)
{   
    struct biza_dev *dev;
    int i = 0;

    BUG_ON(bt == NULL);

    for (i = 0; i < cnt; ++i) {
        dev = &bt->devs[i];
        biza_reset_zone(bt, dev, 0, true);
        kfree(dev->open_zones);
        kfree(dev->iso_dm_state);
        kfree(dev->zones);
    }
}

static int biza_init_devs_open_zones(struct dm_target *ti)
{
    struct biza_target *bt = ti->private;
    struct biza_dev *dev = NULL;
    int i = 0, j = 0;
    int ret = 0;

    for (i = 0; i < bt->params->nr_drives; ++i) {
        dev = &bt->devs[i];

        for(j = 0; j < bt->params->max_nr_zrwa_aware_open_zones; ++j) {
            dev->open_zones[j] = biza_open_empty_zone(bt, dev, true, BIZA_ZRWA_AWARE);
            if(dev->open_zones[j] == dev->nr_zones) {
                ti->error = "Failed to open an zrwa aware zone";
                ret = -EBUSY;
                goto err;
            }
            dev->nr_zrwa_aware_open_zones++;   
        }
        for(; j < bt->params->max_nr_zrwa_aware_open_zones + bt->params->max_nr_lifetime_aware_open_zones; ++j) {
            dev->open_zones[j] = biza_open_empty_zone(bt, dev, true, BIZA_LIFETIME_AWARE);
            if(dev->open_zones[j] == dev->nr_zones) {
                ti->error = "Failed to open an liftime aware zone";
                ret = -EBUSY;
                goto err;
            }
            dev->nr_lifetime_aware_open_zones++;   
        }
        for(; j < bt->params->max_nr_zrwa_aware_open_zones + 
            bt->params->max_nr_lifetime_aware_open_zones + bt->params->max_nr_trivial_open_zones; ++j) {
            dev->open_zones[j] = biza_open_empty_zone(bt, dev, true, BIZA_TRIVIAL);
            if(dev->open_zones[j] == dev->nr_zones) {
                ti->error = "Failed to open an trivial zone";
                ret = -EBUSY;
                goto err;
            }
            dev->nr_trivial_open_zones++;   
        }
        for(; j < bt->params->max_nr_zrwa_aware_open_zones + bt->params->max_nr_lifetime_aware_open_zones
             + bt->params->max_nr_trivial_open_zones + bt->params->max_nr_gc_open_zones; ++j)
        {
            dev->open_zones[j] = biza_open_empty_zone(bt, dev, true, BIZA_GC);
            if(dev->open_zones[j] == dev->nr_zones) {
                ti->error = "Failed to open an gc zone";
                ret = -EBUSY;
                goto err;
            }
            dev->nr_gc_open_zones++;   
        }
    }

    return 0;

err:
    biza_free_devs(bt, i-1);
    return ret;    
}

// Initialize biza drives
static int biza_init_devs(struct dm_target *ti)
{   
    struct biza_target *bt = ti->private;
    struct biza_dev *dev = NULL;
    int i = 0;
    int ret = 0;

    for (i = 0; i < bt->params->nr_drives; ++i) {
        dev = &bt->devs[i];
        
        dev->nr_zones = blkdev_nr_zones(dev->dev->bdev->bd_disk);

        dev->zones = kzalloc(dev->nr_zones * sizeof(struct biza_zone), GFP_KERNEL);
        if (!dev->zones) {
            ti->error = "Failed to allocate dev zones";
            ret = -ENOMEM;
            goto err;
        }

        if (!blkdev_report_zones(dev->dev->bdev, 0, BLK_ALL_ZONES, biza_init_zone, dev)) {
            ti->error = "Failed to report zones";
            ret = -EINVAL;
            goto err_zones;
        }

		/** WARN: Stupid codes **/
		/** WARN: In the future, should get ns_id with ioctl **/        
        dev->ns_id = dev->dev->bdev->bd_disk->disk_name[6] - '0';
        dev->zrwa_size_chunk = BIZA_ZRWASZ * 1024 / bt->params->chunk_size_byte;

        dev->open_zones = kzalloc(sizeof(uint32_t) * bt->params->max_nr_open_zones, GFP_KERNEL);
        if (!dev->open_zones) {
            ti->error = "Failed to allocate dev open zones";
            ret = -ENOMEM;
            goto err_report;
        }

        dev->iso_dm_state = kzalloc(bt->params->nr_isolation_domains * sizeof(biza_iso_dm_state_t), GFP_KERNEL);
        if (!dev->iso_dm_state) {
            ti->error = "Failed to allocate isolation domain state";
            ret = -ENOMEM;
            goto err_report;
        }

        init_rwsem(&dev->ozlock);
        atomic_set(&dev->open_zone_cnt, -1);

        dev->gc_dst_zone_idx = dev->nr_zones;
        dev->avg_lat = 0;
        dev->avg_lat_cnt = 0;
    }

    return 0;

err_report:
    biza_reset_zone(bt, dev, 0, true);
err_zones:
    kfree(dev->zones);
err:
    biza_free_devs(bt, i-1);
    return ret;    
}


static int biza_ctr_mempool(struct biza_mempool *pool, int min_nr, int order)
{   
    int ret, i = 0, j = 0;

    pool->min_nr = min_nr;
    pool->cur_nr = min_nr;
    pool->order = order;
    
    spin_lock_init(&pool->lock);

    pool->elements = kzalloc(sizeof(uint8_t*) * min_nr, GFP_KERNEL);
    if(!pool->elements) {
        pr_err("cannot alloc pool\n");
        ret = -ENOMEM;
        goto err;
    }

    for(i = 0; i < min_nr; ++i) {
        pool->elements[i] = (uint8_t *)__get_free_pages(GFP_KERNEL, order);
        if(!pool->elements[i]) {
            pr_err("cannot alloc pages\n");
            ret = -ENOMEM;
            goto err_pool;
        }
    }

    return 0;

err_pool:
    for(j = 0; j < i; ++j) free_pages((unsigned long)pool->elements[j], order);
    kfree(pool->elements);
err:
    return ret;
}

static void biza_dtr_mempool(struct biza_mempool *pool)
{
    int i;

    /** TODO: Risk of memory leak **/
    for(i = 0; i < pool->cur_nr; ++i) {
        free_pages((unsigned long)pool->elements[i], pool->order);
    }

    kfree(pool->elements);
}

static uint8_t* biza_mempool_alloc(struct biza_mempool *pool) {
   
    uint8_t *element = NULL;
    unsigned long flags;

    spin_lock_irqsave(&pool->lock, flags);
    if(pool->cur_nr > 0) {   
        element = pool->elements[--pool->cur_nr];
    }
    spin_unlock_irqrestore(&pool->lock, flags);

    if(!element) {
        element = (uint8_t *)__get_free_pages(GFP_KERNEL, pool->order);
        // pr_err("mempool run out\n");
    }

    return element;
}

static void biza_mempool_free(struct biza_mempool *pool, uint8_t *element)
{
    unsigned long flags;

    if (unlikely(element == NULL)) return;

    spin_lock_irqsave(&pool->lock, flags);
    if(likely(pool->cur_nr < pool->min_nr)) {
        pool->elements[pool->cur_nr++] = element;
    }
    else free_pages((unsigned long)element, pool->order);
    spin_unlock_irqrestore(&pool->lock, flags);
}

/**
 * Entry of creating biza objects
 */
static int biza_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{   
    struct biza_target *bt = NULL;
    int ret = 0, i = 0;

    if (argc < NUM_DM_BIZA_PARAM + MIN_DEVS) {
		ti->error = "Not enough arguments: <number of drives (k+m)> <fault tolerance (m)> <chunk size (KiB)> \
                    [drives]";
		ret =  -EINVAL;
        goto err;
	}

	// Allocate memory for target
    bt = kzalloc(sizeof(struct biza_target), GFP_KERNEL);
    if (!bt) {
        ti->error = "Failed to allocate biza target";
		ret = -ENOMEM;
        goto err;
    }
    ti->private = bt;

	// Allocate memory for params
    bt->params = kzalloc(sizeof(struct biza_params), GFP_KERNEL);
    if (!bt->params) {
        ti->error = "Failed to allocate biza params";
		ret = -ENOMEM;
        goto err_target;
    }

	// Handle params of AFA
    if (kstrtou8(argv[0], 0, &bt->params->nr_drives)) {
        ti->error = "Invalid number of drives";
        ret = -EINVAL;
        goto err_params;
    }
    if(bt->params->nr_drives < argc - NUM_DM_BIZA_PARAM) {
        ti->error = "Insufficient number of [drives]";
        ret = -EINVAL;
        goto err_params;
    }
    if (kstrtou8(argv[1], 0, &bt->params->m)) {
        ti->error = "Invalid number of fault tolerance";
        ret = -EINVAL;
        goto err_params;
    }
    if (bt->params->m >= bt->params->nr_drives) {
        ti->error = "Fault tolerance shoule be less than the number of drives";
        ret = -EINVAL;
        goto err_params;
    }
    bt->params->k = bt->params->nr_drives - bt->params->m;

	// Handle chunk size
    if (kstrtoull(argv[2], 0, &bt->params->chunk_size_byte)) {
		ti->error = "Invalid chunk size";
		ret = -EINVAL;
        goto err_params;
	}
    bt->params->chunk_size_byte *= 1024;
    bt->params->chunk_size_sector = bt->params->chunk_size_byte >> SECTOR_SHIFT;
    bt->params->chunk_size_sector_shift = ilog2(bt->params->chunk_size_sector);

    /** TODO: Get BIZA_NR_MAX_OPEN_ZONE with ioctl, e.g., nvme_ioctl, nvme_report_zones, nvme_submit_sync_cmd **/ 
    bt->params->max_nr_open_zones = BIZA_NR_MAX_OPEN_ZONE;

    bt->params->max_nr_zrwa_aware_open_zones = NR_ZRWA_AWARE_OPEN_ZONES;
    bt->params->max_nr_lifetime_aware_open_zones = NR_LIFETIME_AWARE_OPEN_ZONES;
    bt->params->max_nr_trivial_open_zones = NR_TRIVIAL_OPEN_ZONES;
    bt->params->max_nr_gc_open_zones = NR_GC_OPEN_ZONES;
    
    // Get # of isolation domains, i.e., # of I/O channels of a ZNS SSD
    bt->params->nr_isolation_domains = BIZA_NR_ISOLATION_DOMAIN;


    // Allocate memory for devs
    bt->devs = kcalloc(bt->params->nr_drives, sizeof(struct biza_dev), GFP_KERNEL);
    if (!bt->devs) {
        ti->error = "Failed to allocate biza devs";
		ret = -ENOMEM;
        goto err_params;
    }

    // Get drives
    for (i = 0; i < bt->params->nr_drives; ++i) {
        if (dm_get_device(ti, argv[NUM_DM_BIZA_PARAM + i], dm_table_get_mode(ti->table), &bt->devs[i].dev)) {
            ti->error = "Failed to get drives";
		    ret = -EINVAL;
            goto err_dev;
        }
    }

    // Initialize drives
    ret = biza_init_devs(ti);
    if (ret) {
        ti->error = "Cannot init drives";
        goto err_dev;
    }

	/** WARN: All SSD should be the same **/
    bt->params->nr_zones_per_drive = bt->devs[0].nr_zones;
    bt->params->zone_capacity_chunk = bt->devs[0].zones[0].capacity >> bt->params->chunk_size_sector_shift;
    bt->params->nr_chunks = bt->params->k * bt->params->nr_zones_per_drive * bt->params->zone_capacity_chunk;
    bt->params->nr_internal_chunks = bt->params->nr_drives * bt->params->nr_zones_per_drive * bt->params->zone_capacity_chunk;

    // Handle GC limit
    bt->gc_limit_high = BIZA_GC_LIMIT_HIGH;
    bt->gc_limit_low = BIZA_GC_LIMIT_LOW;

    // Initialize GC context
    ret = biza_ctr_gc(bt);
    if (ret) {
		ti->error = "Failed to init gc context";
		goto err_zones;
	}

    // Initialize mapping tables
    ret = biza_ctr_map(bt);
    if (ret) {
		ti->error = "Failed to init map context";
		goto err_gc;
	}

    // Initialize I/O queues and locks
    bt->iowq = alloc_workqueue("biza_iowq", WQ_MEM_RECLAIM | WQ_UNBOUND, NUM_SUBMIT_WORKER);
    if (!bt->iowq) {
        ti->error = "Failed to create io workqueue";
        ret = -ENOMEM;
        goto err_map;
    }
    mutex_init(&bt->io_lock);
    INIT_RADIX_TREE(&bt->io_rxtree, GFP_NOIO);

    // Initialize stripe number counter
    atomic64_set(&bt->strip_no_cnt, -1);

    // Initialize partial stripe list
    INIT_LIST_HEAD(&bt->pshl);
    spin_lock_init(&bt->pshl_lock);

    // Initialize full stripe head cache
    xa_init(&bt->fshc);

    // Initialize data cache;
    xa_init(&bt->dc);
    ret = biza_ctr_mempool(&bt->dcpool, BIZA_DATA_CACHE_SIZE, bt->params->chunk_size_sector_shift - PAGE_SECTORS_SHIFT);
    if (ret) {
        ti->error = "Failed to create data cache";
        ret = -ENOMEM;
        goto err_fshc;
    }

    // Initialize parity cache
    ret = biza_ctr_mempool(&bt->pcpool, BIZA_PARITY_CACHE_SIZE, bt->params->chunk_size_sector_shift - PAGE_SECTORS_SHIFT);
    if (ret) {
        ti->error = "Failed to create parity cache";
        ret = -ENOMEM;
        goto err_dc;
    }

	// Initialize pred context (i.e., zone group selector related data structures)
    mutex_init(&bt->pred_lock);
    ret = biza_ctr_pred(bt);
    if (ret) {
		ti->error = "Failed to init pred context";
		goto err_gr;
	}

    // Initialize bio set
    ret = bioset_init(&bt->bio_set, BIZA_BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
    if (ret) {
        ti->error = "Failed to create bio set";
		goto err_lru;
    }

    ret = biza_init_devs_open_zones(ti);
    if(ret) {
        goto err_lru;
    }

    // statistics for write amplification
    atomic64_set(&bt->user_send, 0);
    atomic64_set(&bt->data_write, 0);
    atomic64_set(&bt->parity_write, 0);
    atomic64_set(&bt->data_in_place_update, 0);
    atomic64_set(&bt->parity_in_place_update, 0);

    // Settings for block device layer
    ti->per_io_data_size = sizeof(struct biza_bioctx);
    ti->len = bt->params->nr_chunks << bt->params->chunk_size_sector_shift;

    return 0;


err_lru:
    biza_dtr_pred(bt);
err_gr:
    mutex_destroy(&bt->pred_lock);
    biza_dtr_mempool(&bt->pcpool);
err_dc:
    biza_dtr_mempool(&bt->dcpool);
    xa_destroy(&bt->dc);
err_fshc:
    xa_destroy(&bt->fshc);
    mutex_destroy(&bt->io_lock);
    destroy_workqueue(bt->iowq);
err_map:
    biza_dtr_map(bt);
err_gc:
    biza_dtr_gc(bt);
err_zones:
    biza_free_devs(bt, bt->params->nr_drives);
err_dev:
    kfree(bt->devs);
err_params:
    kfree(bt->params);
err_target:
    kfree(bt);
err:
    pr_err("dm-biza: ctr error: %s\n", ti->error);
    return ret;
}


// 析构函数，biza对象退出前调用
static void biza_dtr(struct dm_target *ti)
{
    struct biza_target *bt = ti->private;
    struct biza_stripe *stripe;
    int i;

    biza_dtr_pred(bt);
    mutex_destroy(&bt->pred_lock);
    biza_dtr_mempool(&bt->pcpool);
    biza_dtr_mempool(&bt->dcpool);
    xa_destroy(&bt->dc);
    xa_destroy(&bt->fshc);
    mutex_destroy(&bt->io_lock);
    flush_workqueue(bt->iowq);
    destroy_workqueue(bt->iowq);
    for(i = 0; i < atomic64_read(&bt->strip_no_cnt); ++i) {
        stripe = xa_load(&bt->map->stripe_table, i);
        if(stripe) kfree(stripe);
        xa_erase(&bt->map->stripe_table, i);
    }
	biza_dtr_map(bt);
    biza_dtr_gc(bt);
    biza_free_devs(bt, bt->params->nr_drives);
    kfree(bt->devs);
    kfree(bt->params);
    kfree(bt);
}


// Initialize the bio context
static inline void biza_init_bioctx(struct biza_target *bt, struct bio *bio)
{
    struct biza_bioctx *bioctx = dm_per_bio_data(bio, sizeof(struct biza_bioctx));

    bioctx->bt = bt;
	refcount_set(&bioctx->ref, 1);
}


// Free stripe head
static void biza_free_stripe_head(struct biza_target *bt, biza_stripe_head_t *sh) {
    // kvfree(sh->parity_cache);
    biza_mempool_free(&bt->pcpool, sh->parity_cache);
    kfree(sh);
}

// Allocate an empty stripe head & init
static biza_stripe_head_t* biza_alloc_empty_stripe_head(struct biza_target *bt)
{
    biza_stripe_head_t *sh = kzalloc(sizeof(biza_stripe_head_t), GFP_KERNEL);
    
    if(sh) {
        sh->no = atomic64_inc_return(&bt->strip_no_cnt); // Started with 0
        sh->nr_data_written = 0;

        // sh->parity_cache = kvzalloc(bt->params->m * bt->params->chunk_size_byte, GFP_KERNEL);
        sh->parity_cache = biza_mempool_alloc(&bt->pcpool);
        if (!sh->parity_cache) {
            pr_err("dm-biza: io error: cannot alloc parity cache");
            goto err;
        }
    }

    return sh;

err:
    kfree(sh);
    return NULL;
}


// Get a partially written stripe head
static biza_stripe_head_t* biza_get_partial_stripe_head(struct biza_target *bt)
{   
    biza_stripe_head_t *sh = NULL;
    
    spin_lock_irq(&bt->pshl_lock);
    // sh = list_first_or_null_rcu(&bt->pshl, biza_stripe_head_t, link);
    sh = list_first_entry_or_null(&bt->pshl, biza_stripe_head_t, link);
    if(sh) {
        list_del(&sh->link);
        spin_unlock_irq(&bt->pshl_lock);
    }
    else {
        spin_unlock_irq(&bt->pshl_lock);
        sh = biza_alloc_empty_stripe_head(bt);
    }

    return sh;
}


// Get a stripe head from cache using stripe no
static biza_stripe_head_t* biza_get_stripe_head_with_no(struct biza_target *bt, uint64_t no) 
{
    biza_stripe_head_t *sh = NULL, *cur = NULL, *tmp = NULL;

    // Try to get from pshl
    spin_lock_irq(&bt->pshl_lock);
    list_for_each_entry_safe(cur, tmp, &bt->pshl, link) {
        if(cur->no == no) {
            sh = cur;
            list_del(&cur->link);
        }
    }
    spin_unlock_irq(&bt->pshl_lock);

    // Try to get from fshc
    if(!sh) {
        sh = xa_load(&bt->fshc, no);
        if(sh) xa_erase_irq(&bt->fshc, no);
    }

    return sh;
}



// Compute parities 
static int biza_compute_parity(struct biza_target *bt, struct bio *bio, biza_stripe_head_t *sh, uint8_t chunk_cnt)
{   
    void **chunks = kzalloc((chunk_cnt + bt->params->m) * sizeof(uint64_t *), GFP_KERNEL);
    uint8_t *bvec_start, *data_start;
    int i = 0, this_cnt = 0, src_off = 0;

    if(bt->params->m != 1) {
        pr_err("dm-biza: io error: only support RAID 5 now");
        return -EDOM;
    } 

    bvec_start = bvec_kmap_local(&bio->bi_io_vec[0]);
    data_start = bvec_start + bio->bi_iter.bi_bvec_done;
    for (i = 0; i < chunk_cnt; ++i) {
        chunks[i] = data_start + i * bt->params->chunk_size_byte;
    }
    for(i = 0; i < bt->params->m; ++i) {
        chunks[chunk_cnt + i] = sh->parity_cache + i * bt->params->chunk_size_byte;
    }

    for(i = 0; i < bt->params->m; ++i) {
        src_off = 0;
        while (chunk_cnt > 0) {
            this_cnt = min(chunk_cnt, (uint8_t)MAX_XOR_BLOCKS);

            xor_blocks(this_cnt, bt->params->chunk_size_byte, chunks[chunk_cnt+i], chunks + src_off);
            
            chunk_cnt -= this_cnt;
            src_off += this_cnt;
        }
    }
    kunmap_local(bvec_start);
    kfree(chunks);

    return 0;
}



// Get aware type (i.e., ZRWA aware, GC aware, and trival)
static inline biza_aware_type biza_oz_idx_to_aware_type(struct biza_target *bt, uint8_t drive_idx, uint8_t oz_idx)
{
    struct biza_dev *dev = &bt->devs[drive_idx];
    BUG_ON(bt->params->max_nr_zrwa_aware_open_zones != dev->nr_zrwa_aware_open_zones);
    BUG_ON(bt->params->max_nr_lifetime_aware_open_zones != dev->nr_lifetime_aware_open_zones);
    BUG_ON(bt->params->max_nr_trivial_open_zones != dev->nr_trivial_open_zones);

    if(oz_idx < dev->nr_zrwa_aware_open_zones) return BIZA_ZRWA_AWARE;
    else if (oz_idx < dev->nr_zrwa_aware_open_zones + dev->nr_lifetime_aware_open_zones) return BIZA_LIFETIME_AWARE;
    else if(oz_idx < dev->nr_zrwa_aware_open_zones + dev->nr_lifetime_aware_open_zones + dev->nr_trivial_open_zones) return BIZA_TRIVIAL;
    else BUG_ON(1);
}

// Try to shift the zrwa window left
static inline bool biza_zrwa_wd_shift(struct biza_target *bt, uint8_t drive_idx, uint8_t oz_idx, uint32_t zone_idx)
{
    struct biza_dev *dev = &bt->devs[drive_idx];
    struct biza_zone *zone = &dev->zones[zone_idx];
    uint64_t wp_off = (zone->wp - zone->start) >> bt->params->chunk_size_sector_shift;
    // uint64_t wp_off = (atomic64_read(&zone->wp) - zone->start) >> bt->params->chunk_size_sector_shift;
    sector_t pcn, lcn;
    uint64_t stripe_no;
    biza_stripe_head_t *sh;
    uint8_t *data_buffer;
    int ret;
    
    // other worker is opening a new empty zone and it release the zone lock
    if(wp_off >= bt->params->zone_capacity_chunk) return false;

    // not in using & used
    if(!test_bit(0, zone->zrwa_wd)) {
        pcn = biza_idx_to_pcn(bt, drive_idx, zone_idx, wp_off);
        lcn = biza_map_pcn_lookup_lcn(bt, pcn);
        if(lcn != BIZA_MAP_UNMAPPED && lcn != BIZA_MAP_INVALID) {
            if(lcn == BIZA_MAP_PARITY) {
                stripe_no = biza_map_pcn_lookup_stripe_no(bt, pcn);
                sh = xa_load(&bt->fshc, stripe_no);
                if(sh) {
                    xa_erase(&bt->fshc, stripe_no);
                    biza_free_stripe_head(bt, sh);
                    // pr_err("free parity buffer, pcn %llu\n", pcn);
                }
            }
            else {
                // 清除data cache
                data_buffer = xa_load(&bt->dc, pcn);
                BUG_ON(!data_buffer);
                xa_erase(&bt->dc, pcn);
                biza_mempool_free(&bt->dcpool, data_buffer);
                // pr_err("free data buffer, drive_idx %u, zone_idx %u, offset %llu\n", drive_idx, zone_idx, wp_off);
            }

            // 滑动ZRWA window
            zone->wp += bt->params->chunk_size_sector;
            // pr_err("drive_idx %u, zone_idx %u, zone_wp add, now: %llu\n", drive_idx, zone_idx, zone->wp);
            // atomic64_add(bt->params->chunk_size_sector, &zone->wp);
            
            if(zone->wp < zone->start + zone->capacity) {
            // if(atomic64_read(&zone->wp) < zone->start + zone->capacity) {
                bitmap_shift_right(zone->zrwa_wd,zone->zrwa_wd,1,dev->zrwa_size_chunk);
                // pr_err("drive_idx %u, zone_idx %u, wp %llu, wp_off %llu, shift, cnt %u, zrwa %x\n", drive_idx, zone_idx, zone->wp, wp_off, atomic_inc_return(&zone->debug_cnt), (uint16_t)*zone->zrwa_wd);
            }
            else { // 这个zone使用完了
                zone->cond = BLK_ZONE_COND_FULL;
                // pr_err("drive_idx %u, zone_idx %u full\n", drive_idx, dev->open_zones[oz_idx]);
                spin_unlock_irq(&zone->zlock);
                
                up_read(&dev->ozlock);
                down_write(&dev->ozlock);
                ret = biza_finish_zone(bt, dev, zone_idx); 
                dev->open_zones[oz_idx] = biza_open_empty_zone(bt, dev, true, biza_oz_idx_to_aware_type(bt, drive_idx, oz_idx));
                // pr_err("drive_idx %u, oz_idx %u open new zone %u\n", drive_idx, oz_idx, dev->open_zones[oz_idx]);
                if(dev->open_zones[oz_idx] == dev->nr_zones) BUG_ON(1);
                downgrade_write(&dev->ozlock);

                zone_idx = dev->open_zones[oz_idx];
                zone = &dev->zones[zone_idx];
                spin_lock_irq(&zone->zlock);
            }
            
            return true;
        }
    }

    return false;
}

// Find a empty zrwa enry for a active zone, return zrwa_size_chunk if none
// return ~((ulong) 0) if no empty
// need zone lock
static inline ulong biza_find_empty_zrwa_enry(struct biza_target *bt, uint8_t drive_idx, uint32_t zone_idx)
{
    struct biza_dev *dev = &bt->devs[drive_idx];
    struct biza_zone *zone = &dev->zones[zone_idx];
    uint64_t wp_off = (zone->wp - zone->start) >> bt->params->chunk_size_sector_shift;
    // uint64_t wp_off = (atomic64_read(&zone->wp) - zone->start) >> bt->params->chunk_size_sector_shift;
    ulong bit_off = 0;
    sector_t pcn, lcn, left;

    left = min(dev->zrwa_size_chunk, bt->params->zone_capacity_chunk - wp_off);
    while (bit_off < left) {
        // not in use
        bit_off = bitmap_find_next_zero_area(zone->zrwa_wd, left, bit_off, 1, 0);
        if(bit_off >= left) break;
        // & not used, i.e., this entry has no valid data
        pcn = biza_idx_to_pcn(bt, drive_idx, zone_idx, wp_off + bit_off);
        lcn = biza_map_pcn_lookup_lcn(bt, pcn);
        if(lcn == BIZA_MAP_UNMAPPED || lcn == BIZA_MAP_INVALID) break;
        bit_off++;
    }

    if(bit_off >= left) return ~((ulong) 0);
    else return bit_off;
}

// test and clear the bit in zrwa window
static inline bool biza_test_and_clear_zrwa_bit(struct biza_target *bt, sector_t pcn, bool irq)
{
    uint8_t drive_idx;
    uint32_t zone_idx;
    uint64_t offset;
    struct biza_dev *dev;
    struct biza_zone *zone;
    uint64_t wp_off;
    ulong bit_off;
    bool org_bit;

    biza_pcn_to_idx(bt, pcn, &drive_idx, &zone_idx, &offset);
    dev = &bt->devs[drive_idx];
    zone = &dev->zones[zone_idx];
    
    if(irq) spin_lock_irq(&zone->zlock);
    else spin_lock(&zone->zlock);
    wp_off = (zone->wp - zone->start) >> bt->params->chunk_size_sector_shift;
    // wp_off = (atomic64_read(&zone->wp) - zone->start) >> bt->params->chunk_size_sector_shift;
    bit_off = offset - wp_off;
    BUG_ON(wp_off + bit_off > bt->params->zone_capacity_chunk);
    org_bit = test_and_clear_bit(bit_off, zone->zrwa_wd);
    // pr_err("drive_idx %u, zone_idx %u, wp %llu, wp_off %llu, bit_off %lu, clear, cnt %u, zrwa %x\n", drive_idx, zone_idx, zone->wp, wp_off, bit_off, atomic_inc_return(&zone->debug_cnt), (uint16_t)*zone->zrwa_wd);
    if(irq) spin_unlock_irq(&zone->zlock);
    else spin_unlock(&zone->zlock);

    return org_bit;
}

// test and set the bit in zrwa window
static inline bool biza_test_and_set_zrwa_bit(struct biza_target *bt, sector_t pcn)
{
    uint8_t drive_idx;
    uint32_t zone_idx;
    uint64_t offset;
    struct biza_dev *dev;
    struct biza_zone *zone;
    uint64_t wp_off;
    ulong bit_off;
    bool org_bit;

    biza_pcn_to_idx(bt, pcn, &drive_idx, &zone_idx, &offset);
    dev = &bt->devs[drive_idx];
    zone = &dev->zones[zone_idx];
    
    spin_lock_irq(&zone->zlock);
    wp_off = (zone->wp - zone->start) >> bt->params->chunk_size_sector_shift;
    // wp_off = (atomic64_read(&zone->wp) - zone->start) >> bt->params->chunk_size_sector_shift;
    bit_off = offset - wp_off;
    BUG_ON(wp_off + bit_off > bt->params->zone_capacity_chunk);
    org_bit = test_and_set_bit(bit_off, zone->zrwa_wd);
    // pr_err("drive_idx %u, zone_idx %u, wp %llu, wp_off %llu, bit_off %lu, set, biza_test_and_set_zrwa_bit, cnt %u, zrwa %x\n", drive_idx, zone_idx, zone->wp, wp_off, bit_off, atomic_inc_return(&zone->debug_cnt), (uint16_t)*zone->zrwa_wd);
    spin_unlock_irq(&zone->zlock);

    return org_bit;
}

// Which zone to write?
// For parallel write
static bool biza_get_zone_write_location(struct biza_target *bt, uint8_t drive_idx, uint8_t oz_idx, 
                                         uint32_t *zone_idx, uint64_t *offset)
{
    struct biza_dev *dev = &bt->devs[drive_idx];
    struct biza_zone *zone;
    uint64_t wp_off;
    uint64_t bit_off;
    bool org_bit;

    while(1) {
        down_read(&dev->ozlock);
        *zone_idx = dev->open_zones[oz_idx];
        zone = &dev->zones[*zone_idx];
        if(zone->cond == BLK_ZONE_COND_FULL) {
            up_read(&dev->ozlock);
            udelay(1);
            continue;
        }

        spin_lock_irq(&zone->zlock);
        wp_off = (zone->wp - zone->start) >> bt->params->chunk_size_sector_shift;
        // wp_off = (atomic64_read(&zone->wp) - zone->start) >> bt->params->chunk_size_sector_shift;
        bit_off = biza_find_empty_zrwa_enry(bt, drive_idx, *zone_idx);
        
        if (bit_off == ~((ulong) 0)) {
            if(biza_zrwa_wd_shift(bt, drive_idx, oz_idx, *zone_idx)) {
                *zone_idx = dev->open_zones[oz_idx];
                zone = &dev->zones[*zone_idx];
                spin_unlock_irq(&zone->zlock);    
                up_read(&dev->ozlock);
            }
            else {
                spin_unlock_irq(&zone->zlock);
                up_read(&dev->ozlock);
                io_schedule_timeout(HZ);
            }
        }
        else {
            org_bit = test_and_set_bit(bit_off, zone->zrwa_wd);
            // pr_err("drive_idx %u, zone_idx %u, wp %llu, wp_off %llu, bit_off %llu, set, biza_get_zone_write_location, cnt %u, zrwa %x\n", drive_idx, *zone_idx, zone->wp, wp_off, bit_off, atomic_inc_return(&zone->debug_cnt), (uint16_t)*zone->zrwa_wd);
            if(!org_bit) {
                spin_unlock_irq(&zone->zlock);
                up_read(&dev->ozlock);
                break;
            } 
            else {
                spin_unlock_irq(&zone->zlock);
                up_read(&dev->ozlock);
            }
        }
    }

    *offset = wp_off + bit_off;

    return true;
}

// Get a write location and set the zrwa window
static inline void biza_get_write_location(struct biza_target *bt, uint64_t hint, uint8_t drive_idx, uint32_t *zone_idx, uint64_t *offset) 
{    
    uint8_t oz_idx;
    int ret;

    oz_idx = biza_choose_open_zone_to_write(bt, drive_idx, hint);
    ret = biza_get_zone_write_location(bt, drive_idx, oz_idx, zone_idx, offset);
    BUG_ON(!ret);
}

// alloc a stripe head io ctx
struct biza_stripe_head_ioctx *biza_alloc_stripe_head_ioctx(struct biza_target *bt, uint8_t data_wrt_cnt)
{   
    struct biza_stripe_head_ioctx *shioctx = NULL;
    
    shioctx = kzalloc(sizeof(struct biza_stripe_head_ioctx), GFP_KERNEL);
    if(!shioctx) goto err;

    shioctx->data_pcns = kvzalloc(data_wrt_cnt * sizeof(sector_t), GFP_KERNEL);
    if(!shioctx->data_pcns) goto err_shioctx;

    shioctx->parity_pcns = kvzalloc(bt->params->m * sizeof(sector_t), GFP_KERNEL);
    if(!shioctx->parity_pcns) goto err_data;

    refcount_set(&shioctx->ref, 1);

    return shioctx;

err_data:
    kvfree(shioctx->data_pcns);
err_shioctx:
    kfree(shioctx);
err:
    return NULL;
}

// Free stripe head io ctx
inline void biza_free_stripe_head_ioctx(struct biza_stripe_head_ioctx *shioctx)
{
    kvfree(shioctx->parity_pcns);
    kvfree(shioctx->data_pcns);
    kfree(shioctx);
}

// can the data of pcn be updated in place (i.e., in ZRWA window & not in use)
static bool biza_can_chunk_update_in_place(struct biza_target *bt, uint64_t pcn)
{
    uint8_t drive_idx;
    uint32_t zone_idx;
    uint64_t offset;
    struct biza_dev *dev;
    struct biza_zone *zone;
    uint64_t wp_off;
    ulong bit_off;
    bool ret;


    biza_pcn_to_idx(bt, pcn, &drive_idx, &zone_idx, &offset);
    dev = &bt->devs[drive_idx];
    zone = &dev->zones[zone_idx];
    
    spin_lock_irq(&zone->zlock);
    wp_off = (zone->wp - zone->start) >> bt->params->chunk_size_sector_shift;
    // wp_off = (atomic64_read(&zone->wp) - zone->start) >> bt->params->chunk_size_sector_shift;
    bit_off = offset - wp_off;
    if(wp_off > offset) ret = false;
    else if(bit_off > dev->zrwa_size_chunk) ret = false;
    else ret = !test_bit(bit_off, zone->zrwa_wd);
    spin_unlock_irq(&zone->zlock);

    return ret;
}

// can the data of lcn (& its parities) be updated in place (i.e., in ZRWA window & not in use)
static inline bool biza_can_data_update_in_place(struct biza_target *bt, uint64_t lcn)
{
    sector_t pcn;
    struct biza_stripe *stripe;
    int i;

    pcn = biza_map_lcn_lookup_pcn(bt, lcn);
    if(pcn == BIZA_MAP_INVALID || pcn == BIZA_MAP_UNMAPPED) return false;

    stripe = biza_map_lcn_lookup_stripe(bt, lcn);
    if(!stripe) return false;


    if(!biza_can_chunk_update_in_place(bt, pcn)) return false;    
    for(i = 0; i < bt->params->m; ++i) {
        pcn = stripe->parity_pcns[i];
        if(pcn == BIZA_MAP_INVALID || pcn == BIZA_MAP_UNMAPPED || pcn > bt->params->nr_chunks) return false;
        if(!biza_can_chunk_update_in_place(bt, pcn)) return false;
    }

    return true;
}

// pin the zrwa (data and parities) for date update in place & get sh
static biza_stripe_head_t* biza_data_update_pin_zrwa_get_sh(struct biza_target *bt, uint64_t lcn)
{
    sector_t pcn;
    uint64_t stripe_no;
    biza_stripe_head_t* sh = NULL;
    struct biza_stripe *stripe;
    int i, j;

    stripe_no = biza_map_lcn_lookup_stripe_no(bt, lcn);
    sh = biza_get_stripe_head_with_no(bt, stripe_no);
    if(!sh) return NULL;

    sh->ioctx = biza_alloc_stripe_head_ioctx(bt, 1);

    pcn = biza_map_lcn_lookup_pcn(bt, lcn);
    stripe = biza_map_lcn_lookup_stripe(bt, lcn);
    if(!stripe) goto fail_sh;

    if(pcn > bt->params->nr_internal_chunks || biza_test_and_set_zrwa_bit(bt, pcn)) {
        goto fail_sh;
    }
    sh->ioctx->data_pcns[0] = pcn;

    for(i = 0; i < bt->params->m; ++i) {
        pcn = stripe->parity_pcns[i];
        if(pcn > bt->params->nr_internal_chunks || biza_test_and_set_zrwa_bit(bt, pcn)) {
            pcn = sh->ioctx->data_pcns[0];
            BUG_ON(!biza_test_and_clear_zrwa_bit(bt, pcn, true));
            for(j = 0; j < i; ++j) {
                pcn = stripe->parity_pcns[j];
                BUG_ON(!biza_test_and_clear_zrwa_bit(bt, pcn, true));
            }

            goto fail_sh;
        }
        sh->ioctx->parity_pcns[i] = pcn;
    }

    return sh;

fail_sh:
    if(sh->nr_data_written == bt->params->k) {
        xa_store_irq(&bt->fshc, sh->no, sh, GFP_KERNEL);
    }
    else {
        spin_lock_irq(&bt->pshl_lock);
        list_add_tail(&sh->link, &bt->pshl);
        spin_unlock_irq(&bt->pshl_lock);
    }
    biza_free_stripe_head_ioctx(sh->ioctx);
    return NULL;
}


// Target BIO completion.
inline void biza_bio_endio(struct bio *bio, blk_status_t status) 
{
    struct biza_bioctx *bioctx = dm_per_bio_data(bio, sizeof(struct biza_bioctx));

    if (status != BLK_STS_OK && bio->bi_status == BLK_STS_OK)
		bio->bi_status = status;

    if (refcount_dec_and_test(&bioctx->ref)) {
		bio_endio(bio);
	}
}


// A stripe head is completed
static void stripe_head_endio(biza_stripe_head_t *sh)
{   
    struct biza_stripe_head_ioctx *shioctx = sh->ioctx;
    struct bio *bio = shioctx->bio;
    struct biza_bioctx *bioctx = dm_per_bio_data(bio, sizeof(struct biza_bioctx));
    struct biza_target *bt = bioctx->bt;
    blk_status_t status = shioctx->status;

    // Update mapping tables
    if(shioctx->type == BIZA_SH_WRITE) {
        sh->nr_data_written += shioctx->data_wrt_cnt;
        BUG_ON(sh->nr_data_written > bt->params->k);
    }

    if(sh->nr_data_written == bt->params->k) {
		/** Add to another list. Release until ZRWA window has slided left. **/
        sh->ioctx = NULL;
        xa_store(&bt->fshc, sh->no, sh, GFP_ATOMIC);
    }
    else {
        spin_lock(&bt->pshl_lock);
        sh->ioctx = NULL;
        list_add_tail(&sh->link, &bt->pshl);
        spin_unlock(&bt->pshl_lock);
    }
    
    biza_free_stripe_head_ioctx(shioctx);

    biza_bio_endio(bio, status);
}


static inline void biza_end_stripe_head_io(biza_stripe_head_t *sh, blk_status_t status)
{   
    struct biza_stripe_head_ioctx *shioctx = sh->ioctx;

    if (status != BLK_STS_OK && shioctx->status == BLK_STS_OK)
		shioctx->status = status;

    if (refcount_dec_and_test(&shioctx->ref)) {
        stripe_head_endio(sh);
    }
}


static void biza_chunkio_endio(struct bio *chunkio)
{
    struct biza_chunkioctx *chunkioctx = chunkio->bi_private;
    struct bio *bio;
    biza_stripe_head_t *sh;
    blk_status_t status = chunkio->bi_status;
    uint8_t drive_idx;
    uint32_t zone_idx;
    uint64_t offset;
    int ret;

    if(unlikely(status != BLK_STS_OK)) {
        pr_err("dm-biza: io failed! io_type %d, bi_status %d, offset %lld, sectors %u", 
                bio_op(chunkio), status, chunkio->bi_iter.bi_sector, bio_sectors(chunkio));
    }
    
    if (chunkioctx->type == BIZA_DATA_WRITE || chunkioctx->type == BIZA_PARITY_WRITE 
        || chunkioctx->type == BIZA_DATA_UPDATE || chunkioctx->type == BIZA_PARITY_UPDATE) {
        
        sh = chunkioctx->sh;

        if(chunkioctx->type == BIZA_DATA_WRITE) {
            biza_map_update_data_wrt(chunkioctx->bt, chunkioctx->lcn, chunkioctx->pcn, sh->no, chunkioctx->slot);
        }
        else if(chunkioctx->type == BIZA_PARITY_WRITE) {
            biza_map_update_parity_wrt(chunkioctx->bt, chunkioctx->pcn, sh->no, chunkioctx->slot);
        }

        ret = biza_test_and_clear_zrwa_bit(chunkioctx->bt, chunkioctx->pcn, false);
        if(!ret) {
            biza_pcn_to_idx(chunkioctx->bt, chunkioctx->pcn, &drive_idx, &zone_idx, &offset);
            BUG_ON(1);
        }

        biza_gc_avoid_stat(chunkioctx);

        kfree(chunkioctx);
        bio_put(chunkio);

        biza_end_stripe_head_io(sh, status);
    }
    else if(chunkioctx->type == BIZA_DATA_READ) {
        bio = chunkioctx->bio;

        kfree(chunkioctx);
        bio_put(chunkio);

        biza_bio_endio(bio, status);
    }
    else BUG_ON(1);
} 


// Send stripe I/O to SSDs
static int biza_submit_stripe_head_write(struct biza_target *bt, struct bio *bio, biza_stripe_head_t *sh, uint8_t chunk_cnt)
{   
    struct biza_stripe_head_ioctx *shioctx = sh->ioctx;
    struct bio *chunkio;
    struct biza_chunkioctx *chunkioctx;
    uint8_t drive_idx;
    uint32_t zone_idx;
    uint64_t offset;
    sector_t lcn, pcn;
    uint8_t *data_buffer, *bvec_start;
    int i, ret;

    BUG_ON(shioctx == NULL);

    // send data chunk I/O 
    for (i = 0; i < chunk_cnt; ++i) {
        lcn = sh->ioctx->lcn_start + i;

        // update 
        biza_update_pred(bt, lcn);

        // Data update in place
        if (shioctx->type == BIZA_SH_IN_PLACE_UPDATE) {
            pcn = sh->ioctx->data_pcns[0];
            BUG_ON(pcn == BIZA_MAP_UNMAPPED || pcn == BIZA_MAP_INVALID);
            biza_pcn_to_idx(bt, pcn, &drive_idx, &zone_idx, &offset);

            if(WRITE_AMP_STAT) atomic64_add(bt->params->chunk_size_sector, &bt->data_in_place_update);
        }
        else {
            drive_idx = (sh->nr_data_written + i + sh->no + bt->params->m) % bt->params->nr_drives;
            biza_get_write_location(bt, lcn, drive_idx, &zone_idx, &offset);
            pcn = biza_idx_to_pcn(bt, drive_idx, zone_idx, offset);

            if(WRITE_AMP_STAT) atomic64_add(bt->params->chunk_size_sector, &bt->data_write);
            
            // store data in cache
            data_buffer = biza_mempool_alloc(&bt->dcpool);
            // pr_err("alloc data buffer, drive_idx %u, zone_idx %u, offset %llu, lcn %llu\n", drive_idx, zone_idx, offset, lcn);
            if(!data_buffer) BUG_ON(1);

            bvec_start = bvec_kmap_local(&bio->bi_io_vec[0]);
            memcpy(data_buffer, bvec_start + bio->bi_iter.bi_bvec_done, bt->params->chunk_size_byte);
            kunmap_local(bvec_start);
            xa_store_irq(&bt->dc, pcn, data_buffer, GFP_KERNEL);
        }

        chunkio = bio_clone_fast(bio, GFP_NOIO, &bt->bio_set);
        if (!chunkio) return -ENOMEM;

        bio_set_dev(chunkio, bt->devs[drive_idx].dev->bdev);
        chunkio->bi_iter.bi_sector = biza_idx_to_sector(bt, drive_idx, zone_idx, offset);
        chunkio->bi_iter.bi_size = bt->params->chunk_size_byte;
        chunkio->bi_end_io = biza_chunkio_endio;

        chunkioctx = kzalloc(sizeof(struct biza_chunkioctx), GFP_NOIO);
        if (!chunkioctx) return -ENOMEM;
        chunkioctx->sh = sh;
        chunkioctx->type = shioctx->type == BIZA_SH_IN_PLACE_UPDATE? BIZA_DATA_UPDATE : BIZA_DATA_WRITE;
        chunkioctx->stime = jiffies;
        chunkioctx->bt = bt;
        chunkioctx->lcn = lcn;
        chunkioctx->pcn = biza_idx_to_pcn(bt, drive_idx, zone_idx, offset);
        chunkioctx->slot = sh->nr_data_written + i;

        chunkio->bi_private = chunkioctx;

        shioctx->data_pcns[i] = biza_idx_to_pcn(bt, drive_idx, zone_idx, offset);
        refcount_inc(&shioctx->ref);

        submit_bio_noacct(chunkio);

        bio_advance(bio, bt->params->chunk_size_byte);
    }

    
    // send parity chunk I/O
    for (i = 0; i < bt->params->m; ++i) {
        if (shioctx->type == BIZA_SH_IN_PLACE_UPDATE) {
            pcn = sh->ioctx->parity_pcns[i];
            BUG_ON(pcn == BIZA_MAP_UNMAPPED || pcn == BIZA_MAP_INVALID);
            biza_pcn_to_idx(bt, pcn, &drive_idx, &zone_idx, &offset);

            if(WRITE_AMP_STAT) atomic64_add(bt->params->chunk_size_sector, &bt->parity_in_place_update);
        }
        else if (sh->nr_data_written > 0) { // try in place update
            pcn = biza_map_parity_lookup_pcn(bt, sh->no, i);
            BUG_ON(pcn == BIZA_MAP_UNMAPPED || pcn == BIZA_MAP_INVALID);

            if (biza_can_chunk_update_in_place(bt, pcn)) {
                ret = biza_test_and_set_zrwa_bit(bt, pcn);
                if(!ret) biza_pcn_to_idx(bt, pcn, &drive_idx, &zone_idx, &offset);
                else {
                    // pr_err("out of place paritial parity update 0\n");
                    drive_idx = (sh->no + i) % bt->params->nr_drives;
                    biza_get_write_location(bt, sh->ioctx->lcn_start, drive_idx, &zone_idx, &offset);
                }

                if(WRITE_AMP_STAT) atomic64_add(bt->params->chunk_size_sector, &bt->parity_in_place_update);
            }
            else {
                // pr_err("out of place paritial parity update 1\n");
                drive_idx = (sh->no + i) % bt->params->nr_drives;
                biza_get_write_location(bt, sh->ioctx->lcn_start, drive_idx, &zone_idx, &offset);

                if(WRITE_AMP_STAT) atomic64_add(bt->params->chunk_size_sector, &bt->parity_write);
            }
        }
        else {
            drive_idx = (sh->no + i) % bt->params->nr_drives;
            biza_get_write_location(bt, sh->ioctx->lcn_start, drive_idx, &zone_idx, &offset);
            
            if(WRITE_AMP_STAT) atomic64_add(bt->params->chunk_size_sector, &bt->parity_write);
        }

        chunkio = bio_alloc_bioset(GFP_NOIO, 1, &bt->bio_set);
        if (!chunkio) return -ENOMEM;

        bio_set_op_attrs(chunkio, REQ_OP_WRITE, bio->bi_opf);
        ret = bio_add_page(chunkio, virt_to_page(sh->parity_cache + i * bt->params->chunk_size_byte),
                           bt->params->chunk_size_byte, 0);
        if (ret != bt->params->chunk_size_byte) return -EIO;
        
        bio_set_dev(chunkio, bt->devs[drive_idx].dev->bdev);
        chunkio->bi_iter.bi_sector = biza_idx_to_sector(bt, drive_idx, zone_idx, offset);
        chunkio->bi_iter.bi_size = bt->params->chunk_size_byte;
        chunkio->bi_end_io = biza_chunkio_endio;

        chunkioctx = kzalloc(sizeof(struct biza_chunkioctx), GFP_NOIO);
        if (!chunkioctx) return -ENOMEM;
        chunkioctx->sh = sh;
        chunkioctx->type = shioctx->type == BIZA_SH_IN_PLACE_UPDATE? BIZA_PARITY_UPDATE : BIZA_PARITY_WRITE;;
        chunkioctx->bt = bt;
        chunkioctx->lcn = BIZA_MAP_PARITY;
        chunkioctx->pcn = biza_idx_to_pcn(bt, drive_idx, zone_idx, offset);
        chunkioctx->slot = i;

        chunkio->bi_private = chunkioctx;

        shioctx->parity_pcns[i] = biza_idx_to_pcn(bt, drive_idx, zone_idx, offset);
        refcount_inc(&shioctx->ref);

        submit_bio_noacct(chunkio);
    }

    biza_end_stripe_head_io(sh, BLK_STS_OK);

    return 0;
}


// Process write request of a full stripe
static int biza_handle_full_stripe_write(struct biza_target *bt, struct bio *bio)
{
    biza_stripe_head_t *sh;
    struct biza_bioctx *bioctx = dm_per_bio_data(bio, sizeof(struct biza_bioctx));
    int ret;

    sh = biza_alloc_empty_stripe_head(bt);
    if(!sh) {
        pr_err("dm-biza: io error: cannot alloc empty stripe");
        return -ENOMEM;
    }
    sh->ioctx = biza_alloc_stripe_head_ioctx(bt, bt->params->k);
    if(!sh->ioctx) {
        pr_err("dm-biza: io error: cannot alloc stripe head ioctx");
        return -ENOMEM;
    }
    sh->ioctx->bio = bio;
    sh->ioctx->data_wrt_cnt = bt->params->k;
    sh->ioctx->lcn_start = bio->bi_iter.bi_sector >> bt->params->chunk_size_sector_shift;
    sh->ioctx->type = BIZA_SH_WRITE;
    refcount_inc(&bioctx->ref);

    ret = biza_compute_parity(bt, bio, sh, bt->params->k);
    if (ret) {
        pr_err("dm-biza: io error: compute parity error");
        return -EIO;
    }

    ret = biza_submit_stripe_head_write(bt, bio, sh, bt->params->k);
    if (ret) {
        pr_err("dm-biza: io error: cannot submit full stripe write");
        return -EIO;
    }

    return 0;
}

// Process write request of a partial stripe  
static int biza_handle_partial_stripe_write(struct biza_target *bt, struct bio *bio, uint8_t chunk_cnt)
{   
    biza_stripe_head_t *sh;
    struct biza_bioctx *bioctx = dm_per_bio_data(bio, sizeof(struct biza_bioctx));
    uint8_t nr_data_write;
    int ret;

    while(chunk_cnt > 0) {
        sh = biza_get_partial_stripe_head(bt);
        if (!sh) {
            pr_err("dm-biza: io error: cannot get partial stripe");
            return -ENOMEM;
        }

        nr_data_write = min(chunk_cnt, (uint8_t)(bt->params->k - sh->nr_data_written));
        sh->ioctx = biza_alloc_stripe_head_ioctx(bt, nr_data_write);
        if (!sh->ioctx) {
            pr_err("dm-biza: io error: cannot alloc stripe head ioctx");
            return -ENOMEM;
        }
        sh->ioctx->bio = bio;
        sh->ioctx->data_wrt_cnt = nr_data_write;
        sh->ioctx->lcn_start = bio->bi_iter.bi_sector >> bt->params->chunk_size_sector_shift;
        sh->ioctx->type = BIZA_SH_WRITE;
        refcount_inc(&bioctx->ref);

        ret = biza_compute_parity(bt, bio, sh, nr_data_write);
        if (ret) {
            pr_err("dm-biza: io error: compute parity error");
            return -ENOMEM;
        }
        
        ret = biza_submit_stripe_head_write(bt, bio, sh, nr_data_write);
        if (ret) {
            pr_err("dm-biza: io error: cannot submit paritial stripe write");
            return -EIO;
        }

        chunk_cnt -= nr_data_write;
    }

    return 0;
}


// Process in place update write request
static int biza_handle_data_in_place_update(struct biza_target *bt, struct bio *bio, biza_stripe_head_t *sh)
{
    void **srcs = kzalloc(sizeof(uint64_t *), GFP_KERNEL);
    struct biza_bioctx *bioctx = dm_per_bio_data(bio, sizeof(struct biza_bioctx));
    sector_t lcn, pcn;
    uint8_t *org_data, *bvec_start;
    int ret;

    lcn = bio->bi_iter.bi_sector >> bt->params->chunk_size_sector_shift;
    pcn = biza_map_lcn_lookup_pcn(bt, lcn);

    org_data = xa_load(&bt->dc, pcn);
    BUG_ON(!org_data);

    if (!sh->ioctx) BUG_ON(1);
    sh->ioctx->bio = bio;
    sh->ioctx->data_wrt_cnt = 1;
    sh->ioctx->lcn_start = lcn;
    sh->ioctx->type = BIZA_SH_IN_PLACE_UPDATE;
    refcount_inc(&bioctx->ref);

    /** recompute parity **/
    BUG_ON(bt->params->m != 1);
    // P' = P + D + D'
    // P + D = D^ (result in P)
    srcs[0] = org_data;
    xor_blocks(1, bt->params->chunk_size_byte, sh->parity_cache, srcs);

    // compute D^ + D' = P'
    bvec_start = bvec_kmap_local(&bio->bi_io_vec[0]);
    srcs[0] = bvec_start + bio->bi_iter.bi_bvec_done;
    xor_blocks(1, bt->params->chunk_size_byte, sh->parity_cache, srcs);

    // update data_buffer
    memcpy(org_data, srcs[0], bt->params->chunk_size_byte);
    kunmap_local(bvec_start);

    kfree(srcs);

    /** submit stripe head **/
    ret = biza_submit_stripe_head_write(bt, bio, sh, 1);
    if (ret) {
        pr_err("dm-biza: io error: cannot submit data update in place");
        return -EIO;
    }

    return 0;
}


// Process a write request
static int biza_handle_write(struct biza_target *bt, struct bio *bio)
{   
    sector_t left, cur_lcn;
    uint8_t chunk_cnt;
    biza_stripe_head_t *sh;
    int ret;

    if (bio_sectors(bio) % bt->params->chunk_size_sector || bio->bi_iter.bi_sector % bt->params->chunk_size_sector) {
        BUG_ON(1);
    }

    left = bio_sectors(bio) >> bt->params->chunk_size_sector_shift;

    if(WRITE_AMP_STAT) atomic64_add(bio_sectors(bio), &bt->user_send);

    while (left > 0) {
        cur_lcn = bio->bi_iter.bi_sector >> bt->params->chunk_size_sector_shift;

        if (biza_can_data_update_in_place(bt, cur_lcn)) {
            sh = biza_data_update_pin_zrwa_get_sh(bt, cur_lcn);
            if(sh) {
                ret = biza_handle_data_in_place_update(bt, bio, sh);
                if(ret) return -EIO;

                left = bio_sectors(bio) >> bt->params->chunk_size_sector_shift;
                continue;
            } 
        }

        chunk_cnt = 0;

        // while (chunk_cnt < left && chunk_cnt < bt->params->k) {
        while (chunk_cnt < left && chunk_cnt < bt->params->k && !biza_can_data_update_in_place(bt, cur_lcn)) {
            cur_lcn++;
            chunk_cnt++;   
        }

        if (chunk_cnt == bt->params->k) {
            ret = biza_handle_full_stripe_write(bt, bio);
            if(ret) return -EIO;
        }
        else if (chunk_cnt > 0 && chunk_cnt < bt->params->k) {
            ret = biza_handle_partial_stripe_write(bt, bio, chunk_cnt);
            if(ret) return -EIO;
        }
        else BUG_ON(chunk_cnt != 0);

        left = bio_sectors(bio) >> bt->params->chunk_size_sector_shift;
    }

    return 0;
}


// Send chunk I/O to SSD
static int biza_submit_chunk_read(struct biza_target *bt, struct bio *bio, sector_t pcn, sector_t size)
{
    struct biza_bioctx *bioctx = dm_per_bio_data(bio, sizeof(struct biza_bioctx));
    struct bio *chunkio;
    struct biza_chunkioctx *chunkioctx;
    uint8_t drive_idx;
    uint32_t zone_idx;
    uint64_t offset;

    if(pcn == BIZA_MAP_UNMAPPED || pcn == BIZA_MAP_INVALID) {
        swap(bio->bi_iter.bi_size, size);
        zero_fill_bio(bio);
        swap(bio->bi_iter.bi_size, size);
    }
    else {
        biza_pcn_to_idx(bt, pcn, &drive_idx, &zone_idx, &offset);

        chunkio = bio_clone_fast(bio, GFP_NOIO, &bt->bio_set);
        if(!chunkio) return -ENOMEM;

        bio_set_dev(chunkio, bt->devs[drive_idx].dev->bdev);
        chunkio->bi_iter.bi_sector = biza_idx_to_sector(bt, drive_idx, zone_idx, offset);
        chunkio->bi_iter.bi_size = size;
        chunkio->bi_end_io = biza_chunkio_endio;

        chunkioctx = kzalloc(sizeof(struct biza_chunkioctx), GFP_NOIO);
        if(!chunkioctx) return -ENOMEM;
        chunkioctx->bio = bio;
        chunkioctx->type = BIZA_DATA_READ;
        chunkioctx->bt = bt;
        chunkioctx->pcn = pcn;
        
        chunkio->bi_private = chunkioctx;
        
        refcount_inc(&bioctx->ref);
        submit_bio_noacct(chunkio);
    }

    bio_advance(bio, size);

    return 0;
}


// Process a read request
static int biza_handle_read(struct biza_target *bt, struct bio *bio)
{   
    sector_t cur_sec, nxt_sec, size, left;
    sector_t lcn, pcn;
    int ret;

    left = bio_sectors(bio);

    while (left > 0) {
        cur_sec = bio->bi_iter.bi_sector;
        // e.g., chunk = 128 sec, 0->128, 32->128
        nxt_sec = min(round_up(cur_sec + 1, bt->params->chunk_size_sector), bio_end_sector(bio)); 
        size = (nxt_sec - cur_sec) << SECTOR_SHIFT;

        lcn = cur_sec >> bt->params->chunk_size_sector_shift;
        pcn = biza_map_lcn_lookup_pcn(bt, lcn);
        
        ret = biza_submit_chunk_read(bt, bio, pcn, size);
        if(ret) {
            pr_err("dm-biza: io error: cannot submit chunk read");
            return -EIO;
        }

        left = bio_sectors(bio);
    }

    return 0;
}


// Entry of I/O handling
static void biza_handle_bio(struct biza_target *bt, struct bio *bio)
{   
    enum req_opf op;
    int ret;

    if(bio->bi_vcnt > 1) {
        /** TODO: support bi_vcnt > 1 **/ 
        pr_err("dm-biza: map error: bvec cnt > 1 %d", bio->bi_vcnt);
        biza_bio_endio(bio, -EIO);
        return;
    }
    
    op = bio_op(bio);
    if(op == REQ_OP_WRITE) {
        mutex_lock(&bt->gc_schedule_lock);
        biza_schedule_gc(bt);
        mutex_unlock(&bt->gc_schedule_lock);
    }

    switch(op){
    case REQ_OP_READ:
        ret = biza_handle_read(bt, bio);
        break;
    case REQ_OP_WRITE:
        ret = biza_handle_write(bt, bio);
        break;
    default:
        pr_err("dm-biza: map error: Unsupported bio type 0x%x", bio_op(bio));
        ret = -EIO;
    }

    biza_bio_endio(bio, errno_to_blk_status(ret));
}


/*
 * Increment a chunk reference counter.
 */
static inline void biza_get_io_work(struct biza_io_work *iowork)
{
    refcount_inc(&iowork->ref);
}

/*
 * Decrement a io work reference count and
 * free it if it becomes 0.
 */
static void biza_put_io_work(struct biza_io_work *iowork)
{
	if (refcount_dec_and_test(&iowork->ref)) {
		BUG_ON(!bio_list_empty(&iowork->bio_list));
		radix_tree_delete(&iowork->bt->io_rxtree, iowork->lcn);
		kfree(iowork);
	}
}

// IO work
static void biza_io_work(struct work_struct *work) 
{
    struct biza_io_work *iowork = container_of(work, struct biza_io_work, work);
    struct biza_target *bt = iowork->bt;
    struct bio *bio;

    mutex_lock(&bt->io_lock);

    /* Process the BIOs target at the lcn */
    while((bio = bio_list_pop(&iowork->bio_list))) {
        mutex_unlock(&bt->io_lock);
        biza_handle_bio(bt, bio);
        mutex_lock(&bt->io_lock);
        biza_put_io_work(iowork);
    }
    
    /* Queueing the work incremented the work refcount */
    biza_put_io_work(iowork);

    mutex_unlock(&bt->io_lock);
}


/*
 * Get a I/O work and start it to process a new BIO.
 * If the BIO chunk has no work yet, create one.
 */
static int biza_queue_io_work(struct biza_target *bt, struct bio *bio)
{   
    sector_t lcn = bio->bi_iter.bi_sector >> bt->params->chunk_size_sector_shift;
    struct biza_io_work *iowork;
    int ret = 0;

    mutex_lock(&bt->io_lock);

    /* Get the BIO chunk work. If one is not active yet, create one */
    iowork = radix_tree_lookup(&bt->io_rxtree, lcn);
    if(iowork) {
        biza_get_io_work(iowork);
    }
    else {
        iowork = kzalloc(sizeof(struct biza_io_work), GFP_NOIO);
        if(unlikely(!iowork)) {
            ret = -ENOMEM;
            goto out;
        }

        INIT_WORK(&iowork->work, biza_io_work);
        refcount_set(&iowork->ref, 1);
        iowork->bt = bt;
        iowork->lcn = lcn;
        bio_list_init(&iowork->bio_list);

        ret = radix_tree_insert(&bt->io_rxtree, lcn, iowork);
        if(unlikely(ret)) {
            kfree(iowork);
            goto out;
        }
    }

    bio_list_add(&iowork->bio_list, bio);

    /* Upadate access time*/
	biza_gc_update_accese_time(bt);

    if(queue_work(bt->iowq, &iowork->work))
        biza_get_io_work(iowork);

out:
    mutex_unlock(&bt->io_lock);
    return ret;
}


static int biza_map(struct dm_target *ti, struct bio *bio)
{
    struct biza_target *bt = ti->private;
    sector_t nr_sectors = bio_sectors(bio);
    int ret;

    if (!nr_sectors && bio_op(bio) != REQ_OP_WRITE)
		return DM_MAPIO_REMAPPED;

    biza_init_bioctx(bt, bio);

    /* Set the BIO pending in the flush list */
	if (!nr_sectors && bio_op(bio) == REQ_OP_WRITE) {
        /** TODO: support flush **/ 
        pr_err("dm-biza: io error, nr_sectors = 0 & op = write");
        return DM_MAPIO_KILL;
    }

    /* Now ready to handle this BIO */
	ret = biza_queue_io_work(bt, bio);
	if (ret) {
		pr_debug("BIO op %d, can't process offset %llu, err %i",
			bio_op(bio), bio->bi_iter.bi_sector,
			ret);
		return DM_MAPIO_REQUEUE;
	}
    
    return DM_MAPIO_SUBMITTED;
}

/*
 * Setup target request queue limits.
 */
static void biza_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct biza_target *bt = ti->private;

	limits->logical_block_size = bt->params->chunk_size_byte;
	limits->physical_block_size = bt->params->chunk_size_byte;

	blk_limits_io_min(limits, bt->params->chunk_size_byte);
	blk_limits_io_opt(limits, bt->params->chunk_size_byte * bt->params->k);

	/* FS hint to try to align to the device zone size */
	limits->chunk_sectors = bt->params->chunk_size_sector;

	/* We are exposing a host-managed zoned block device */
	limits->zoned = BLK_ZONED_NONE;
}

// Module
static struct target_type biza_target = {
    .name = "biza",
    .version = { 1, 0, 0 },
	.module = THIS_MODULE,
    .ctr = biza_ctr,
    .dtr = biza_dtr,
    .map = biza_map,
	.io_hints = biza_io_hints
};

static int __init init_biza(void)
{
	return dm_register_target(&biza_target);
} 

static void __exit cleanup_biza(void)
{
    dm_unregister_target(&biza_target);
}

module_init(init_biza);
module_exit(cleanup_biza);

MODULE_DESCRIPTION("A software RAID engine which provides block interface for ZNS SSD array");
MODULE_AUTHOR("Shushu Yi <shusyi@stu.pku.edu.cn>");
MODULE_LICENSE("GPL");
