#include "dm-biza.h"

// alloc and init a stripe (not stripe head!!!)
static struct biza_stripe * biza_alloc_stripe(struct biza_target *bt)
{
    struct biza_stripe *stripe = NULL;
    int i;

    stripe = kzalloc(sizeof(struct biza_stripe), GFP_ATOMIC);
    if(!stripe) goto err;

    stripe->parity_pcns = kvzalloc(bt->params->m * sizeof(sector_t), GFP_ATOMIC); 
    if(!stripe->parity_pcns) goto err_stripe;
    for(i = 0; i < bt->params->m; ++i) {
        stripe->parity_pcns[i] = BIZA_MAP_UNMAPPED;
    }

    stripe->data_lcns = kvzalloc(bt->params->k * sizeof(sector_t), GFP_ATOMIC); 
    if(!stripe->data_lcns) goto err_parity;
    for(i = 0; i < bt->params->k; ++i) {
        stripe->data_lcns[i] = BIZA_MAP_UNMAPPED;
    }

    stripe->used = 0;
    stripe->valid = 0;

    return stripe;

err_parity:
    kvfree(stripe->parity_pcns);
err_stripe:
    kfree(stripe);
err:
    return NULL;
}

// free a stripe (not stripe head!!!)
static void biza_free_stripe(struct biza_stripe *stripe)
{
    kvfree(stripe->data_lcns);
    kvfree(stripe->parity_pcns);
    kfree(stripe);
}

/**
 * idx to sector (in drive)
 */
inline sector_t biza_idx_to_sector(struct biza_target *bt, uint8_t drive_idx, uint32_t zone_idx, uint64_t offset)
{
    BUG_ON(zone_idx > bt->params->nr_zones_per_drive);
    
    return (zone_idx * bt->devs[drive_idx].zones[0].len) + (offset << bt->params->chunk_size_sector_shift);
}

/**
 * idx to pcn
 */
inline sector_t biza_idx_to_pcn(struct biza_target *bt, uint8_t drive_idx, uint32_t zone_idx, uint64_t offset)
{
    sector_t pcn = (drive_idx * bt->params->nr_zones_per_drive + zone_idx) * bt->params->zone_capacity_chunk + offset;
    
    if(drive_idx >= bt->params->nr_drives) {
        BUG_ON(1);
    }
    BUG_ON(zone_idx >= bt->params->nr_zones_per_drive);
    if(offset >= bt->params->zone_capacity_chunk) {
        BUG_ON(1);
    }

    return pcn;
}

/**
 * pcn to idx
 */
inline void biza_pcn_to_idx(struct biza_target *bt, sector_t pcn, uint8_t *drive_idx, uint32_t *zone_idx, uint64_t *offset)
{
    *drive_idx = pcn / (bt->params->nr_zones_per_drive * bt->params->zone_capacity_chunk);
    *zone_idx = (pcn % (bt->params->nr_zones_per_drive * bt->params->zone_capacity_chunk)) / bt->params->zone_capacity_chunk;
    *offset = pcn % bt->params->zone_capacity_chunk;

    if(*drive_idx >= bt->params->nr_drives) {
        BUG_ON(1);
    }
    BUG_ON(*zone_idx >= bt->params->nr_zones_per_drive);
    if(*offset >= bt->params->zone_capacity_chunk) {
        BUG_ON(1);
    }
}


// Lookup physical chunk number of chunk from lcn
inline sector_t biza_map_lcn_lookup_pcn(struct biza_target *bt, sector_t lcn)
{
    sector_t pcn;
    // struct biza_stripe *stripe;

    BUG_ON(lcn == BIZA_MAP_UNMAPPED || lcn == BIZA_MAP_INVALID || lcn == BIZA_MAP_PARITY);

    pcn = bt->map->l2p[lcn].chunk_no;

    return pcn;
}

// Lookup logical chunk number of chunk from pcn
inline sector_t biza_map_pcn_lookup_lcn(struct biza_target *bt, sector_t pcn)
{
    sector_t lcn;

    BUG_ON(pcn == BIZA_MAP_UNMAPPED || pcn == BIZA_MAP_INVALID || pcn == BIZA_MAP_PARITY);
    BUG_ON(pcn >= bt->params->nr_internal_chunks);

    lcn = bt->map->p2l[pcn].chunk_no;

    return lcn;
}

// Lookup physical chunk number of parity
inline sector_t biza_map_parity_lookup_pcn(struct biza_target *bt, uint64_t no, uint8_t slot)
{
    sector_t pcn;
    struct biza_stripe *stripe;
    
    stripe = xa_load(&bt->map->stripe_table, no);
    if (!stripe) pcn = BIZA_MAP_UNMAPPED;
    else pcn = stripe->parity_pcns[slot];


    return pcn;

}

// Lookup stripe no
inline sector_t biza_map_lcn_lookup_stripe_no(struct biza_target *bt, sector_t lcn)
{
    uint64_t stripe_no;

    stripe_no = bt->map->l2p[lcn].stripe_no;

    return stripe_no;
}

// Lookup stripe
inline struct biza_stripe * biza_map_lcn_lookup_stripe(struct biza_target *bt, sector_t lcn)
{
    uint64_t stripe_no;
    struct biza_stripe *stripe;

    stripe_no = bt->map->l2p[lcn].stripe_no;
    stripe = xa_load(&bt->map->stripe_table, stripe_no);

    return stripe;
}

// Lookup stripe
inline uint64_t biza_map_pcn_lookup_stripe_no(struct biza_target *bt, sector_t pcn)
{
    uint64_t stripe_no;

    stripe_no = bt->map->p2l[pcn].stripe_no;

    return stripe_no;
}

// Is the pcn storing valid data?
inline bool biza_map_is_data_in_pcn_useful(struct biza_target *bt, sector_t pcn)
{
    struct biza_stripe *stripe;
    bool ret;

    if(bt->map->p2l[pcn].chunk_no == BIZA_MAP_UNMAPPED || bt->map->p2l[pcn].chunk_no == BIZA_MAP_INVALID) {
        /**
         * WARN: Need modify: can only recycle stirpes with all invalid data now
         */
        if(bt->map->p2l[pcn].stripe_no == BIZA_MAP_UNMAPPED || bt->map->p2l[pcn].stripe_no == BIZA_MAP_INVALID) ret = false;
        else {
            stripe = xa_load(&bt->map->stripe_table, bt->map->p2l[pcn].stripe_no);
            if(stripe) ret = true;
            else ret = false;
        }
    }
    else ret = true;

    return ret;
}


// update mapping tables because of data write/out-of-place update 
void biza_map_update_data_wrt(struct biza_target *bt, sector_t lcn, sector_t pcn, uint64_t no, uint8_t slot)
{
    sector_t org_pcn = BIZA_MAP_UNMAPPED;
    uint64_t org_stripe_no = BIZA_MAP_UNMAPPED;
    uint8_t org_slot = (uint8_t)BIZA_MAP_UNMAPPED;
    struct biza_stripe *stripe = NULL, *org_stripe = NULL;
    uint8_t org_drive_idx;
    uint32_t org_zone_idx;
    uint64_t org_offset;
	sector_t org_parity_pcn = BIZA_MAP_UNMAPPED;
    int i;

    org_pcn = bt->map->l2p[lcn].chunk_no;
    org_stripe_no = bt->map->l2p[lcn].stripe_no;
    org_slot = bt->map->l2p[lcn].slot;
    
    bt->map->l2p[lcn].chunk_no = pcn;
    bt->map->l2p[lcn].stripe_no = no;
    bt->map->l2p[lcn].slot = slot;
    bt->map->p2l[pcn].chunk_no = lcn;
    bt->map->p2l[pcn].stripe_no = no;
    bt->map->p2l[pcn].slot = slot;

    stripe = xa_load(&bt->map->stripe_table, no);
    if(!stripe) {
        stripe = biza_alloc_stripe(bt);
        xa_store(&bt->map->stripe_table, no, stripe, GFP_ATOMIC);
    }
    stripe->data_lcns[slot] = lcn;
    stripe->used++;
    stripe->valid++;

    if(org_pcn != BIZA_MAP_UNMAPPED) {
        bt->map->p2l[org_pcn].chunk_no = BIZA_MAP_INVALID;
        // DO NOT set stripe_no now, because when gc, we need recompute parity
        // bt->map->p2l[org_pcn].stripe_no = BIZA_MAP_INVALID;
        bt->map->p2l[org_pcn].slot = (uint8_t)BIZA_MAP_INVALID;
        biza_pcn_to_idx(bt, org_pcn, &org_drive_idx, &org_zone_idx, &org_offset);
        bt->devs[org_drive_idx].zones[org_zone_idx].nr_invalid_chunks++;
        
        org_stripe = xa_load(&bt->map->stripe_table, org_stripe_no);
        BUG_ON(!org_stripe);
        org_stripe->data_lcns[org_slot] = BIZA_MAP_INVALID;

		// All data in original stripe is invalid
        if (--org_stripe->valid == 0) {
            if(org_stripe->used == bt->params->k) {
                for(i = 0; i < bt->params->m; ++i) {
					org_parity_pcn = org_stripe->parity_pcns[i];
					if(org_parity_pcn >= bt->params->nr_internal_chunks) continue;

                    bt->map->p2l[org_parity_pcn].chunk_no = BIZA_MAP_INVALID;
                    bt->map->p2l[org_parity_pcn].stripe_no = BIZA_MAP_INVALID;
                    bt->map->p2l[org_parity_pcn].slot = (uint8_t)BIZA_MAP_INVALID;
                    biza_pcn_to_idx(bt, org_parity_pcn, &org_drive_idx, 
                                    &org_zone_idx, &org_offset);
                    bt->devs[org_drive_idx].zones[org_zone_idx].nr_invalid_chunks++;
                }
                biza_free_stripe(org_stripe);
                xa_erase(&bt->map->stripe_table, org_stripe_no);
            }
        }
    }
}

// update mapping tables because of parity write/ out-of-place update
void biza_map_update_parity_wrt(struct biza_target *bt, sector_t pcn, uint64_t no, uint8_t slot)
{   
    struct biza_stripe *stripe = NULL;

    stripe = xa_load(&bt->map->stripe_table, no);
    if(!stripe) {
        BUG_ON(slot);
        stripe = biza_alloc_stripe(bt);
        xa_store(&bt->map->stripe_table, no, stripe, GFP_ATOMIC);
    }

    // stripe->parity_pcns[slot] == BIZA_MAP_UNMAPPED
    bt->map->p2l[pcn].chunk_no = BIZA_MAP_PARITY;
    bt->map->p2l[pcn].stripe_no = no;
    bt->map->p2l[pcn].slot = slot;
    stripe->parity_pcns[slot] = pcn;
}


// update map after data/parity moving
// Note that the data/parity storing in src_pcn and dst_pcn should be the same
void biza_map_remap(struct biza_target *bt, sector_t src_pcn, sector_t dst_pcn)
{
    sector_t lcn;
    uint64_t stripe_no;
    uint8_t slot;
    struct biza_stripe *stripe = NULL;

    lcn = bt->map->p2l[src_pcn].chunk_no;
    // be modified while GC
    if(lcn == BIZA_MAP_INVALID || lcn == BIZA_MAP_UNMAPPED) return;

    if(lcn == BIZA_MAP_PARITY) { // parity chunk
        stripe_no = bt->map->p2l[src_pcn].stripe_no;
        slot = bt->map->p2l[src_pcn].slot;
        stripe = xa_load(&bt->map->stripe_table, stripe_no);
        
        // BUG_ON(!stripe);
        // BUG_ON(stripe->parity_pcns[slot] != src_pcn);

        stripe->parity_pcns[slot] = dst_pcn;
    }
    else {  // data chunk
        // BUG_ON(bt->map->l2p[lcn].chunk_no != src_pcn);
        bt->map->l2p[lcn].chunk_no = dst_pcn;
    }
    bt->map->p2l[dst_pcn].chunk_no = bt->map->p2l[src_pcn].chunk_no;
    bt->map->p2l[dst_pcn].stripe_no = bt->map->p2l[src_pcn].stripe_no;
    bt->map->p2l[dst_pcn].slot = bt->map->p2l[src_pcn].slot;

    bt->map->p2l[src_pcn].chunk_no = BIZA_MAP_INVALID;
    bt->map->p2l[src_pcn].stripe_no = BIZA_MAP_INVALID;
    bt->map->p2l[src_pcn].slot = (uint8_t)BIZA_MAP_INVALID;
}

// Initialize map context
int biza_ctr_map(struct biza_target *bt)
{
    int ret;

    bt->map = kzalloc(sizeof(struct biza_map), GFP_KERNEL);
    if (!bt->map) {
        pr_err("dm-biza: Failed to allocate biza map\n");
		ret = -ENOMEM;
    }

    bt->map->l2p = kvmalloc_array(bt->params->nr_chunks, sizeof(biza_addr_t), GFP_KERNEL);
    if (!bt->map->l2p) {
        pr_err("dm-biza: Failed to allocate l2p map\n");
		ret = -ENOMEM;
        goto err_map;
    }
    memset(bt->map->l2p, (uint8_t)BIZA_MAP_UNMAPPED, bt->params->nr_chunks * sizeof(biza_addr_t));

    bt->map->p2l = kvmalloc_array(bt->params->nr_internal_chunks, sizeof(biza_addr_t), GFP_KERNEL);
    if (!bt->map->p2l) {
        pr_err("dm-biza: Failed to allocate p2l map\n");
		ret = -ENOMEM;
        goto err_l2p;
    }
    memset(bt->map->p2l, (uint8_t)BIZA_MAP_UNMAPPED, bt->params->nr_internal_chunks * sizeof(biza_addr_t));

    xa_init(&bt->map->stripe_table);

    return 0;

err_l2p:
    kvfree(bt->map->l2p);
err_map:
    kfree(bt->map);
    return ret;
}

// Destory map context
void biza_dtr_map(struct biza_target *bt)
{
    xa_destroy(&bt->map->stripe_table);
    kvfree(bt->map->p2l);
    kvfree(bt->map->l2p);
    kfree(bt->map);
}