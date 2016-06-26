/*
 * Copyright (C) 2016 Hardkernel Co. Ltd.
 * Copyright (C) 2016 OtherCrashOverride
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.         See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <linux/module.h>

#include <ump/ump_kernel_interface_ref_drv.h>
#include <ump/ump_kernel_interface.h>
#include <asm/uaccess.h>
#include "osd_fb.h"

 // dma_buf
#include <linux/dma-buf.h>
#include <linux/scatterlist.h>
#include <linux/platform_device.h>


static int osd_attach_dma_buf(struct dma_buf *dmabuf,
	struct device *dev,
	struct dma_buf_attachment *attach)
{
	pr_info("osd_attach_dma_buf\n");

	attach->priv = dmabuf->priv;

	return 0;
}

static void osd_detach_dma_buf(struct dma_buf *dmabuf,
	struct dma_buf_attachment *attach)
{
	pr_info("osd_detach_dma_buf\n");
}

static struct sg_table *
osd_map_dma_buf(struct dma_buf_attachment *attach,
	enum dma_data_direction dir)
{
	int ret;
	struct sg_table *sgt = NULL;
	struct fb_info *info = NULL;

	pr_info("osd_map_dma_buf\n");

	// Validate parameters
	if (!attach)
	{
		return NULL;
	}


	// Get the private data
	info = (struct fb_info *)attach->priv;
	if (!info)
	{
		pr_info("osd_map_dma_buf: attach->priv is NULL.\n");
		return NULL;
	}

	// TODO: figure out how to clean this pointer up
	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
	{
		pr_info("osd_map_dma_buf: kzalloc failed.\n");
		return NULL;
	}

	// CMA memory will always have a single entry
	ret = sg_alloc_table(sgt, 1, GFP_KERNEL);
	if (ret) {
		pr_info("failed to alloc sgt.\n");
		return NULL;
	}

	// CMA memory should always be page aligned and,
	// therefore, always have a 0 offset
	sg_set_page(sgt->sgl,
		phys_to_page(info->fix.smem_start),
		info->fix.smem_len,
		0);

	sg_dma_address(sgt->sgl) = info->fix.smem_start;
	sg_dma_len(sgt->sgl) = info->fix.smem_len;

	pr_info("osd_map_dma_buf: sgt=%p, page=%p (%p)\n",
		sgt,
		(void*)phys_to_page(info->fix.smem_start),
		(void*)info->fix.smem_start);

	return sgt;
}

static void osd_unmap_dma_buf(struct dma_buf_attachment *attach,
	struct sg_table *sgt,
	enum dma_data_direction dir)
{
	// TODO: Do we clean up the sg_table* ?
	pr_info("osd_unmap_dma_buf\n");

	kfree(sgt);
}

static void *osd_dmabuf_kmap_atomic(struct dma_buf *dma_buf,
	unsigned long page_num)
{
	/* TODO */
	pr_info("osd_dmabuf_kmap_atomic\n");
	return NULL;
}

static void osd_dmabuf_kunmap_atomic(struct dma_buf *dma_buf,
	unsigned long page_num,
	void *addr)
{
	/* TODO */
	pr_info("osd_dmabuf_kunmap_atomic\n");
}

static void *osd_dmabuf_kmap(struct dma_buf *dma_buf,
	unsigned long page_num)
{
	/* TODO */
	pr_info("osd_dmabuf_kmap\n");
	return NULL;
}

static void osd_dmabuf_kunmap(struct dma_buf *dma_buf,
	unsigned long page_num, void *addr)
{
	/* TODO */
	pr_info("osd_dmabuf_kunmap\n");
}

static int osd_dmabuf_mmap(struct dma_buf *dma_buf,
	struct vm_area_struct *vma)
{
	unsigned long off;
	unsigned vm_size = vma->vm_end - vma->vm_start;
	struct dma_buf_attachment* attach = NULL;
	struct sg_table* sgt = NULL;
	struct scatterlist *sg = NULL;
	dma_addr_t phys;
	unsigned long dmaSize = 0;
	struct fb_info *info;
	struct osd_fb_dev_s *fbdev;

	pr_info("osd_dmabuf_mmap\n");

	if (vm_size == 0)
	{
		return -EAGAIN;
	}


	info = (struct fb_info *)dma_buf->priv;
	fbdev = (struct osd_fb_dev_s *)info->par;

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_IO;

	attach = dma_buf_attach(dma_buf, &fbdev->dev->dev);
	if (!attach)
	{
		pr_info("osd_dmabuf_mmap: dma_buf_attach failed\n");
		return -EAGAIN;
	}
	else
	{
		pr_info("osd_dmabuf_mmap: attach=%p\n", attach);
	}

	sgt = dma_buf_map_attachment(attach, DMA_NONE);
	if (!sgt)
	{
		pr_info("osd_dmabuf_mmap: dma_buf_map_attachment failed\n");
		return -EAGAIN;
	}
	else
	{
		pr_info("osd_dmabuf_mmap: sgt=%p\n", sgt);
	}

	//for_each_sg(sgt->sgl, sg, sgt->nents, i)
	{
		sg = sgt->sgl;
		pr_info("osd_dmabuf_mmap: sg=%p\n", sg);

		dmaSize = sg_dma_len(sg);
		// TODO: Validate size <= dmaSize here

		phys = sg_dma_address(sg);
		pr_info("osd_dmabuf_mmap: phys=%p (%p), length=%p\n",
			(void*)phys,
			(void*)sg->dma_address,
			(void*)dmaSize);

		off = vma->vm_pgoff << PAGE_SHIFT;
		off += (unsigned long)phys;

		if (remap_pfn_range(vma,
			vma->vm_start,
			off >> PAGE_SHIFT,
			vm_size,
			vma->vm_page_prot))
		{
			pr_info("remap_pfn_range failed\n");
			return -EAGAIN;
		}

		pr_info("osd_dmabuf_mmap ok\n");
	}

	return 0;
}

static void osd_dmabuf_release(struct dma_buf *dma_buf)
{
	// TODO
}

static struct dma_buf_ops osd_dmabuf_ops = {
	.attach = osd_attach_dma_buf,
	.detach = osd_detach_dma_buf,
	.map_dma_buf = osd_map_dma_buf,
	.unmap_dma_buf = osd_unmap_dma_buf,
	.kmap = osd_dmabuf_kmap,
	.kmap_atomic = osd_dmabuf_kmap_atomic,
	.kunmap = osd_dmabuf_kunmap,
	.kunmap_atomic = osd_dmabuf_kunmap_atomic,
	.mmap = osd_dmabuf_mmap,
	.release = osd_dmabuf_release,
};

int osd_get_dmabuf_fd(struct fb_info *info,
	struct osd_fb_dev_s *g_fbi, unsigned long arg)
{
	// IOCTL interface
	int __user *dmabuf_fd = (int __user *) arg;
	struct dma_buf* dmabuf;
	int flags = 0;	// No idea what this should be
	int ret = -1;

	pr_info("osd_get_dmabuf_fd\n");

	dmabuf = dma_buf_export(info,
		&osd_dmabuf_ops,
		info->fix.smem_len,
		flags);

	ret = dma_buf_fd(dmabuf, flags);
	pr_info("osd_get_dmabuf_fd- dmabuf=%p, fd=%d\n", dmabuf, ret);

	return put_user(ret, dmabuf_fd);
}
EXPORT_SYMBOL(osd_get_dmabuf_fd);


// UMP

int (*disp_get_ump_secure_id) (struct fb_info *info, 
	struct osd_fb_dev_s *g_fbi,	unsigned long arg, int buf);
EXPORT_SYMBOL(disp_get_ump_secure_id);

static int _disp_get_ump_secure_id(struct fb_info *info, 
	struct osd_fb_dev_s *g_fbi, unsigned long arg, int buf)
{
	u32 __user *psecureid = (u32 __user *) arg;
	ump_secure_id secure_id;

	if (!g_fbi->ump_wrapped_buffer[info->node][buf]) {
		ump_dd_physical_block ump_memory_description;
		printk("ump: create disp: %d\n", buf);

		ump_memory_description.addr = info->fix.smem_start;
		ump_memory_description.size = info->fix.smem_len;
		g_fbi->ump_wrapped_buffer[info->node][buf] =
			ump_dd_handle_create_from_phys_blocks(
				&ump_memory_description, 1);
	}
	secure_id = ump_dd_secure_id_get(
			g_fbi->ump_wrapped_buffer[info->node][buf]);
			
	return put_user((unsigned int)secure_id, psecureid);
}

static int __init osd_ump_module_init(void)
{
	int ret = 0;
	disp_get_ump_secure_id = _disp_get_ump_secure_id;
	return ret;
}

static void __exit osd_ump_module_exit(void)
{
	disp_get_ump_secure_id = NULL;
}

module_init(osd_ump_module_init);
module_exit(osd_ump_module_exit);

MODULE_AUTHOR("Mauro Ribeiro <mauro.ribeiro@hardkernel.com>");
MODULE_DESCRIPTION("UMP Glue for AMLogic OSD Framebuffer");
MODULE_LICENSE("GPL");
