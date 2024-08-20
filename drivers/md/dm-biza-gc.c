#include "dm-biza.h"

// Should do gc?
static inline bool biza_should_gc(struct biza_target *bt) 
{   
    BUG_ON(bt->gc->nr_free_zones > bt->params->nr_zones_per_drive * bt->params->nr_drives);
    BUG_ON(bt->gc->p_free_zones > 100);

    return bt->gc->p_free_zones < bt->gc_limit_high;
}

inline void biza_schedule_gc(struct biza_target *bt) 
{
    if (biza_should_gc(bt)) {
        mod_delayed_work(bt->gc->wq, &bt->gc->work, 0);
    }
}


// Choose a victim zone
static bool biza_select_victim(struct biza_target *bt, uint8_t *drive_idx, uint32_t *zone_idx)
{   
    struct biza_dev *dev;
    uint8_t victim_drive_idx;
    uint32_t victim_zone_idx;
    uint32_t max_invalid_chunk = 0;
    uint64_t nr_invalid_chunks = 0;
    int i;

    BUG_ON(bt->params->m != 1);

    victim_drive_idx = get_random_u32() % bt->params->nr_drives;
    dev = &bt->devs[victim_drive_idx];

    for(i = 0; i < dev->nr_zones; ++i) {
        if(dev->zones[i].cond == BLK_ZONE_COND_FULL) {
            nr_invalid_chunks = dev->zones[i].nr_invalid_chunks;
            if(nr_invalid_chunks > max_invalid_chunk) {
                victim_zone_idx = i;
                max_invalid_chunk = nr_invalid_chunks;
            }
        }
    }

    if(max_invalid_chunk == 0) return false;

    *drive_idx = victim_drive_idx;
    *zone_idx = victim_zone_idx;

    return true;
}

// Get an empty zone for storing valid data
static void biza_gc_choose_dst_zone(struct biza_target *bt, uint8_t *drive_idx, uint32_t *zone_idx, uint8_t *oz_idx)
{
    struct biza_dev *dev;

    *drive_idx = get_random_u32() % bt->params->nr_drives;
    dev = &bt->devs[*drive_idx];
    
    *oz_idx = dev->nr_zrwa_aware_open_zones + dev->nr_lifetime_aware_open_zones + 
             + dev->nr_trivial_open_zones + get_random_u32() % dev->nr_gc_open_zones;
    *zone_idx = dev->open_zones[*oz_idx];
}

// dm_kcopyd_copy end recall
static void bt_gc_kcopy_end(int read_err, ulong write_err, void *context)
{
    struct biza_gc *gc = context;

    if(read_err || write_err) gc->kc_err = -EIO;
    else gc->kc_err = 0;

    clear_bit_unlock(BIZA_GC_KCOPY, &gc->flags);
    smp_mb__after_atomic();
	wake_up_bit(&gc->flags, BIZA_GC_KCOPY);
}

// Tagging isolation domain for GC avoidance
static inline void biza_gc_tag_isolation_domain(struct biza_target *bt, uint8_t drive_idx, uint32_t zone_idx,
                                                biza_iso_dm_state_t state)
{
    struct biza_dev *dev = &bt->devs[drive_idx];
    uint8_t iso_dm = dev->zones[zone_idx].iso_dm;

    BUG_ON(iso_dm >= bt->params->nr_isolation_domains);
    dev->iso_dm_state[iso_dm] = state; 

    if(state == BIZA_GC_DST) dev->gc_dst_zone_idx = zone_idx;
}

static inline void biza_gc_untag_isolation_domain(struct biza_target *bt, uint8_t drive_idx, uint32_t zone_idx)
{
    struct biza_dev *dev = &bt->devs[drive_idx];
    uint8_t iso_dm = dev->zones[zone_idx].iso_dm;

    if(dev->gc_dst_zone_idx == zone_idx) {
        BUG_ON(dev->iso_dm_state[iso_dm] != BIZA_GC_DST);
        dev->gc_dst_zone_idx = dev->nr_zones;
    }

    BUG_ON(iso_dm >= bt->params->nr_isolation_domains);
    dev->iso_dm_state[iso_dm] = BIZA_GC_NORMAL; 
}

// Move valid data from victim zone
static void biza_gc_move_valid_data(struct biza_target *bt, uint8_t src_drive_idx, uint32_t src_zone_idx)
{   
    struct biza_dev *src_dev, *dst_dev;
    struct biza_zone *src_zone, *dst_zone;
    uint8_t dst_drive_idx;
    uint32_t dst_zone_idx;
    uint8_t dst_oz_idx;
    uint64_t src_offset, dst_offset;
    uint64_t src_pcn, dst_pcn;
    struct dm_io_region src, dst;
    ulong flags = 0;

    src_dev = &bt->devs[src_drive_idx];
    src_zone = &src_dev->zones[src_zone_idx];
    biza_gc_choose_dst_zone(bt, &dst_drive_idx, &dst_zone_idx, &dst_oz_idx);
    dst_dev = &bt->devs[dst_drive_idx];
    dst_zone = &dst_dev->zones[dst_zone_idx];

    BUG_ON(src_zone->cond != BLK_ZONE_COND_FULL);
    BUG_ON(dst_zone->cond == BLK_ZONE_COND_FULL);

    biza_gc_tag_isolation_domain(bt, src_drive_idx, src_zone_idx, BIZA_GC_SRC);
    biza_gc_tag_isolation_domain(bt, dst_drive_idx, dst_zone_idx, BIZA_GC_DST);

    set_bit(DM_KCOPYD_WRITE_SEQ, &flags);

    for(src_offset = 0; src_offset < bt->params->zone_capacity_chunk; ++src_offset) {
        src_pcn = biza_idx_to_pcn(bt, src_drive_idx, src_zone_idx, src_offset);
        if(biza_map_is_data_in_pcn_useful(bt, src_pcn)) {
            src.bdev = src_dev->dev->bdev;
            src.sector = biza_idx_to_sector(bt, src_drive_idx, src_zone_idx, src_offset);
            src.count = bt->params->chunk_size_sector;

            dst.bdev = dst_dev->dev->bdev;
            dst.sector = dst_zone->wp;
            dst.count = bt->params->chunk_size_sector;

            set_bit(BIZA_GC_KCOPY, &bt->gc->flags);
            dm_kcopyd_copy(bt->gc->kc, &src, 1, &dst, flags,bt_gc_kcopy_end, bt->gc);

            dst_offset = (dst_zone->wp - dst_zone->start) >> bt->params->chunk_size_sector_shift;
            // dst_offset = (atomic64_read(&dst_zone->wp) - dst_zone->start) >> bt->params->chunk_size_sector_shift;
            dst_pcn = biza_idx_to_pcn(bt, dst_drive_idx, dst_zone_idx, dst_offset);
            biza_map_remap(bt, src_pcn, dst_pcn);

            wait_on_bit_io(&bt->gc->flags, BIZA_GC_KCOPY, TASK_UNINTERRUPTIBLE);
            BUG_ON(bt->gc->kc_err);
            
            dst_zone->wp += bt->params->chunk_size_sector;
            // atomic64_add(bt->params->chunk_size_sector, &dst_zone->wp);
            if(dst_zone->wp >= dst_zone->start + dst_zone->capacity) {
            // if(atomic64_read(&dst_zone->wp) >= dst_zone->start + dst_zone->capacity) {
                dst_zone->cond = BLK_ZONE_COND_FULL;
                biza_gc_untag_isolation_domain(bt, dst_drive_idx, dst_zone_idx);
                dst_dev->open_zones[dst_oz_idx] = biza_open_empty_zone(bt, dst_dev, true, BIZA_GC);
                if(dst_dev->open_zones[dst_oz_idx] == dst_dev->nr_zones) BUG_ON(1);
                dst_zone_idx = dst_dev->open_zones[dst_oz_idx];
                dst_zone = &dst_dev->zones[dst_zone_idx];
                biza_gc_tag_isolation_domain(bt, dst_drive_idx, dst_zone_idx, BIZA_GC_DST);
            }
        }
    }

    biza_gc_untag_isolation_domain(bt, dst_drive_idx, dst_zone_idx);
    biza_gc_untag_isolation_domain(bt, src_drive_idx, src_zone_idx);
}

// Entry of GC
static int biza_do_gc(struct biza_target *bt)
{   
    uint8_t victim_drive_idx;
    uint32_t victim_zone_idx;
    int ret = 0;

    ret = biza_select_victim(bt, &victim_drive_idx, &victim_zone_idx);
    if(ret) {
        biza_gc_move_valid_data(bt, victim_drive_idx, victim_zone_idx);
        biza_reset_zone(bt, &bt->devs[victim_drive_idx], victim_zone_idx, false);
    }
    
    return 0;
}

/*
 * BIO accounting.
 */
void biza_gc_update_accese_time(struct biza_target *bt)
{
	bt->gc->atime = jiffies;
}

/*
 * Test if the target device is idle.
 */
static inline int biza_target_idle(struct biza_target *bt)
{
    return time_is_before_jiffies(bt->gc->atime + BIZA_IDLE_PERIOD);
}

// GC work function
static void biza_gc_work(struct work_struct *work)
{
    struct biza_gc *gc = container_of(work, struct biza_gc, work.work);
    struct biza_target *bt = gc->bt;
    int ret = 0, i;
    struct biza_dev *dev;

    if(WRITE_AMP_STAT) {
        pr_err("user_send %lld, data write %lld, parity write %lld, data in place update %lld, parity in place upate %lld\n",
        atomic64_read(&bt->user_send), atomic64_read(&bt->data_write), atomic64_read(&bt->parity_write), 
        atomic64_read(&bt->data_in_place_update), atomic64_read(&bt->parity_in_place_update));
    }

    if (!biza_should_gc(bt)) {
        mod_delayed_work(gc->wq, &gc->work, BIZA_GC_DETECT_PERIOD);
		return;
    }

    /** GC throttle **/
    if(biza_target_idle(bt) || bt->gc->p_free_zones < bt->gc_limit_low) {
        gc->kc_throttle.throttle = 100;
    }
    else gc->kc_throttle.throttle = BIZA_GC_LOWEST_SPEED + 
        (100 - BIZA_GC_LOWEST_SPEED) / (bt->gc_limit_high - bt->gc_limit_low) * (bt->gc_limit_high - bt->gc->p_free_zones);

    ret = biza_do_gc(bt);
    if (ret) {
        pr_err("dm-biza: Do GC error!");
        BUG_ON(1);
    }
        
    biza_schedule_gc(bt);
}



/**
 * Choose a open zone that can avoid GC in a zone group.
 */
uint8_t biza_get_oz_idx_gc_avoid(struct biza_target *bt, struct biza_dev *dev, uint8_t ozg_idx)
{
    uint8_t oz_idx;
    uint8_t offset_start = get_random_u32() % bt->params->nr_isolation_domains;
    uint32_t zone_idx;
    struct biza_zone *zone;
    int i;

    down_read(&dev->ozlock);
    for(i = 0; i < bt->params->nr_isolation_domains; ++i)
    {
        oz_idx = ozg_idx * BIZA_NR_ISOLATION_DOMAIN + (offset_start + i) % bt->params->nr_isolation_domains;
        zone_idx = dev->open_zones[oz_idx];
        zone = &dev->zones[zone_idx];
        if(dev->iso_dm_state[zone->iso_dm] != BIZA_GC_DST) {
            up_read(&dev->ozlock);
            return oz_idx;
        }
    }
    // oz_idx = ozg_idx * BIZA_NR_ISOLATION_DOMAIN + offset_start % bt->params->nr_isolation_domains;
    up_read(&dev->ozlock);
    
    /** WARN: All zone is in GC **/
    return ozg_idx * BIZA_NR_ISOLATION_DOMAIN + offset_start;
}

void biza_gc_avoid_stat(struct biza_chunkioctx *chunkioctx)
{
    struct biza_target *bt;
    uint64_t pcn;
    uint8_t drive_idx;
    uint32_t zone_idx;
    uint64_t offset;
    struct biza_dev *dev;
    struct biza_zone *zone, *gc_zone;
    unsigned long lat;

    bt = chunkioctx->bt;
    pcn = chunkioctx->pcn;
    lat = jiffies - chunkioctx->stime;

    biza_pcn_to_idx(bt, pcn, &drive_idx, &zone_idx, &offset);
    dev = &bt->devs[drive_idx];
    zone = &dev->zones[zone_idx];

    /** BIZA-DEBUG **/
    if(bt->params->nr_isolation_domains == 1) {
        dev->avg_lat_cnt++;
        dev->avg_lat = dev->avg_lat + (lat - dev->avg_lat) / dev->avg_lat_cnt;
        return;
    }

    BUG_ON(bt->params->nr_isolation_domains != 2);

    // If this dev is in GC
    if(dev->gc_dst_zone_idx < dev->nr_zones){
        gc_zone = &dev->zones[dev->gc_dst_zone_idx];
        if(lat > 5 * dev->avg_lat) {
            if(gc_zone->iso_dm != zone->iso_dm) {
                zone->high_lat_score++;
                if(zone->high_lat_score >= BIZA_HIGH_LAT_AWARE_THRESHOLD) {

                    zone->iso_dm = zone->iso_dm ? 0 : 1;

                    // correct
                    zone->iso_dm_conf--;
                    gc_zone->iso_dm_conf--;
                    
                    if(zone->iso_dm) {
                        zone->iso_dm_vote--;
                        gc_zone->iso_dm_vote++;
                    }
                    else {
                        zone->iso_dm_vote++;
                        gc_zone->iso_dm_vote--;
                    }

                    if(!zone->iso_dm_conf) {
                        BUG_ON(!zone->iso_dm);
                        zone->iso_dm = zone->iso_dm_vote > 0 ? 1 : 0;
                        zone->iso_dm_conf = BIZA_ISO_DOMAIN_CONFIDENCE;
                        zone->iso_dm_vote = 0;
                    }
                    
                    if(!gc_zone->iso_dm_conf) {
                        BUG_ON(!gc_zone->iso_dm);
                        gc_zone->iso_dm = gc_zone->iso_dm_vote > 0 ? 1 : 0;
                        gc_zone->iso_dm_conf = BIZA_ISO_DOMAIN_CONFIDENCE;
                        gc_zone->iso_dm_vote = 0;
                    }
                    zone->high_lat_score = 0;
                }
            }
        }
        zone->high_lat_score = (zone->high_lat_score)? zone->high_lat_score-1 : 0;
    }
    
    dev->avg_lat_cnt++;
    dev->avg_lat = dev->avg_lat + (lat - dev->avg_lat) / dev->avg_lat_cnt;
}


// Initialize GC context
int biza_ctr_gc(struct biza_target *bt)
{
    struct biza_gc *gc;
    int ret = 0;
    
    gc = kzalloc(sizeof(struct biza_gc), GFP_KERNEL);
    if (!gc) {
        pr_err("dm-biza: Cannot alloc gc context\n");
        ret = -ENOMEM;
        goto err; 
    }

    gc->bt = bt;
    gc->nr_free_zones = bt->params->nr_zones_per_drive * bt->params->nr_drives;
    gc->p_free_zones = 100;

    /* GC kcopyd client */
    gc->kc_throttle.throttle = 100;
    gc->kc = dm_kcopyd_client_create(&gc->kc_throttle);
    if (IS_ERR(gc->kc)) {
        pr_err("dm-biza: Cannot alloc gc workqueue\n");
        ret = PTR_ERR(gc->kc);
        gc->kc = NULL;
        goto err;
    }

    /* GC work */
    INIT_DELAYED_WORK(&gc->work, biza_gc_work);
    gc->wq = alloc_ordered_workqueue("biza_gcwq", WQ_MEM_RECLAIM);
    if (!gc->wq) {
        pr_err("dm-biza: Cannot alloc gc workqueue\n");
        ret = -ENOMEM;
        goto err_kc;
    }
    queue_delayed_work(gc->wq, &gc->work, BIZA_GC_DETECT_PERIOD);

    bt->gc = gc;
    bt->gc->atime = jiffies;

    mutex_init(&bt->gc_schedule_lock);

    return 0;

err_kc:
    dm_kcopyd_client_destroy(gc->kc);
err:
    kfree(gc);
    return ret;
}


// Destory GC context
void biza_dtr_gc(struct biza_target *bt)
{   
    mutex_destroy(&bt->gc_schedule_lock);
    cancel_delayed_work_sync(&bt->gc->work);
    destroy_workqueue(bt->gc->wq);
    dm_kcopyd_client_destroy(bt->gc->kc);
    kfree(bt->gc);
}
