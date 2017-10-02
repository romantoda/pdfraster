// PdfRaster.c - functions to write PDF/raster
//

#include <assert.h>
#include <string.h>

#include "PdfRaster.h"
#include "PdfDict.h"
#include "PdfAtoms.h"
#include "PdfStandardAtoms.h"
#include "PdfString.h"
#include "PdfStrings.h"
#include "PdfXrefTable.h"
#include "PdfStandardObjects.h"
#include "PdfImage.h"
#include "PdfArray.h"
#include "PdfSecurityHandler.h"

#include "openssl/crypto.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include "openssl/err.h"
#include "openssl/md5.h"
#include <openssl/rand.h>

typedef struct t_pdfrasencoder {
	t_pdmempool*		pool;
	int					apiLevel;			// caller's specified API level.
	t_pdoutstream*		stm;				// output PDF stream
	void *				writercookie;
	time_t				creationDate;
	t_pdatomtable*		atoms;				// the atom table/dictionary
	// standard document objects
	t_pdxref*			xref;
	t_pdvalue			catalog;
	t_pdvalue			info;
	t_pdvalue			trailer;
	// optional document objects
	t_pdvalue			rgbColorspace;		// current colorspace for RGB images
	pdbool				bitonalUncal;		// use uncalibrated /DeviceGray for bitonal images
	// page parameters, apply to subsequently started pages
    int                 next_page_rotation;
    double              next_page_xdpi;
    double              next_page_ydpi;
	RasterPixelFormat	next_page_pixelFormat;		// how pixels are represented
	RasterCompression	next_page_compression;		// compression setting for next page

    // current page object
	t_pdvalue			currentPage;
    int					strips;				// number of strips on current page
    int					height;				// total pixel height of current page

    // page parameters, established at start of page or when first strip
    // is written
	int					rotation;			// page rotation (degrees clockwise)
	int					width;				// image width in pixels
    double				xdpi;				// horizontal resolution, pixels/inch
    double				ydpi;				// vertical resolution, pixels/inch
    RasterPixelFormat   pixelFormat;        // format of pixels
    RasterCompression   compression;        // compression algorithm
    t_pdvalue           colorspace;         // colorspace
    int					phys_pageno;		// physical page number
    int					page_front;			// front/back/unspecified
} t_pdfrasencoder;


t_pdfrasencoder* pdfr_encoder_create(int apiLevel, t_OS *os)
{
	struct t_pdmempool *pool;

	if (apiLevel < 1) {
		// TODO: report error
		// invalid apiLevel parameter value
		return NULL;
	}
	if (apiLevel > 1) {
		// TODO: report error
		// Caller was compiled for a later version of this API
		return NULL;
	}
	assert(os);
	// create a memory management pool for the internal use of this encoder.
	pool = pd_alloc_new_pool(os);
	assert(pool);

	t_pdfrasencoder *enc = (t_pdfrasencoder *)pd_alloc(pool, sizeof(t_pdfrasencoder));
	if (enc)
	{
		enc->pool = pool;						// associated allocation pool
		enc->apiLevel = apiLevel;				// level of this API assumed by caller
		enc->stm = pd_outstream_new(pool, os);	// our PDF-output stream abstraction

		enc->next_page_rotation = 0;						// default page rotation
		enc->next_page_xdpi = enc->next_page_ydpi = 300;    // default resolution
		enc->next_page_compression = PDFRAS_UNCOMPRESSED;	// default compression for next page
		enc->next_page_pixelFormat = PDFRAS_BITONAL;		// default pixel format
        enc->phys_pageno = -1;			    // unspecified
        enc->page_front = -1;			    // unspecified

		// initial atom table
		enc->atoms = pd_atom_table_new(pool, 128);
		// empty cross-reference table:
		enc->xref = pd_xref_new(pool);
		// initial document catalog:
		enc->catalog = pd_catalog_new(pool, enc->xref);

		// create 'info' dictionary
		enc->info = pd_info_new(pool, enc->xref);
		// and trailer dictionary
		enc->trailer = pd_trailer_new(pool, enc->xref, enc->catalog, enc->info);
		// default Producer
		pd_dict_put(enc->info, PDA_Producer, pdcstrvalue(pool, "PdfRaster encoder " PDFRAS_LIBRARY_VERSION));
		// record creation date & time:
		time(&enc->creationDate);
		pd_dict_put(enc->info, PDA_CreationDate, pd_make_time_string(pool, enc->creationDate));
		// we don't modify PDF so there is no ModDate

		assert(IS_NULL(enc->rgbColorspace));
		assert(IS_NULL(enc->currentPage));

		// Write the PDF header:
		pd_write_pdf_header(enc->stm, "1.4");
	}
	return enc;
}

void pdfr_encoder_set_creator(t_pdfrasencoder *enc, const char* creator)
{
	pd_dict_put(enc->info, PDA_Creator, pdcstrvalue(enc->pool, creator));
}

void pdfr_encoder_set_author(t_pdfrasencoder *enc, const char* author)
{
	pd_dict_put(enc->info, PDA_Author, pdcstrvalue(enc->pool, author));
}

void pdfr_encoder_set_title(t_pdfrasencoder *enc, const char* title)
{
	pd_dict_put(enc->info, PDA_Title, pdcstrvalue(enc->pool, title));
}

void pdfr_encoder_set_subject(t_pdfrasencoder *enc, const char* subject)
{
	pd_dict_put(enc->info, PDA_Subject, pdcstrvalue(enc->pool, subject));
}

void pdfr_encoder_set_keywords(t_pdfrasencoder *enc, const char* keywords)
{
	pd_dict_put(enc->info, PDA_Keywords, pdcstrvalue(enc->pool, keywords));
}

void f_write_string(t_datasink *sink, void *eventcookie)
{
	const char* xmpdata = (const char*)eventcookie;
	pd_datasink_put(sink, xmpdata, 0, pdstrlen(xmpdata));
}

void pdfr_encoder_get_creation_date(t_pdfrasencoder *enc, time_t *t)
{
	*t = enc->creationDate;
}

void pdfr_encoder_write_document_xmp(t_pdfrasencoder *enc, const char* xmpdata)
{
	t_pdvalue xmpstm = pd_metadata_new(enc->pool, enc->xref, f_write_string, (void*)xmpdata);
	// flush the metadata stream to output immediately
	pd_write_reference_declaration(enc->stm, xmpstm);
	pd_dict_put(enc->catalog, PDA_Metadata, xmpstm);
}

void pdfr_encoder_write_page_xmp(t_pdfrasencoder *enc, const char* xmpdata)
{
	t_pdvalue xmpstm = pd_metadata_new(enc->pool, enc->xref, f_write_string, (void*)xmpdata);
	// flush the metadata stream to output immediately
	pd_write_reference_declaration(enc->stm, xmpstm);
	pd_dict_put(enc->currentPage, PDA_Metadata, xmpstm);
}

void pdfr_encoder_set_resolution(t_pdfrasencoder *enc, double xdpi, double ydpi)
{
	enc->next_page_xdpi = xdpi;
	enc->next_page_ydpi = ydpi;
}

// Set the rotation for subsequent pages.
// Values that are not multiple of 90 are *ignored*.
// Valid values are mapped into the range 0, 90, 180, 270.
void pdfr_encoder_set_rotation(t_pdfrasencoder* enc, int degCW)
{
	while (degCW < 0) degCW += 360;
    degCW = degCW % 360;
	if (degCW % 90 == 0) {
		enc->next_page_rotation = degCW;
	}
}

void pdfr_encoder_set_pixelformat(t_pdfrasencoder* enc, RasterPixelFormat format)
{
	enc->next_page_pixelFormat = format;
}

// establishes compression to be used the next time a page is
// started (on first strip write).
void pdfr_encoder_set_compression(t_pdfrasencoder* enc, RasterCompression comp)
{
	enc->next_page_compression = comp;
}

int pdfr_encoder_set_bitonal_uncalibrated(t_pdfrasencoder* enc, int uncal)
{
    int previous = (enc->bitonalUncal != 0);
	enc->bitonalUncal = (uncal != 0);
    return previous;
}

void pdfr_encoder_define_calrgb_colorspace(t_pdfrasencoder* enc, double gamma[3], double black[3], double white[3], double matrix[9])
{
    enc->rgbColorspace =
        pd_make_calrgb_colorspace(enc->pool, gamma, black, white, matrix);
}

void pdfr_encoder_define_rgb_icc_colorspace(t_pdfrasencoder* enc, const pduint8 *profile, size_t len)
{
    if (!profile) {
        enc->rgbColorspace = pd_make_srgb_colorspace(enc->pool, enc->xref);
    }
    else {
        // define the calibrated (ICCBased) colorspace that should
        // be used on RGB images (if they aren't marked DeviceRGB)
        enc->rgbColorspace =
            pd_make_iccbased_rgb_colorspace(enc->pool, enc->xref, profile, len);
    }
}

int pdfr_encoder_start_page(t_pdfrasencoder* enc, int width)
{
	if (IS_DICT(enc->currentPage)) {
		pdfr_encoder_end_page(enc);
	}
    assert(IS_NULL(enc->currentPage));
	enc->width = width;
    // put the 'next page' settings into effect for this page
    enc->xdpi = enc->next_page_xdpi;
    enc->ydpi = enc->next_page_ydpi;
    enc->rotation = enc->next_page_rotation;
    // reset strip count and row count
	enc->strips = 0;				// number of strips written to current page
	enc->height = 0;				// height of current page so far

	double W = width / enc->xdpi * 72.0;
	// Start a new page (of unknown height)
	enc->currentPage = pd_page_new_simple(enc->pool, enc->xref, enc->catalog, W, 0);
	assert(IS_REFERENCE(enc->currentPage));
  assert(IS_DICT(pd_reference_get_value(enc->currentPage)));

  //rt
  if (is_digsig == PD_TRUE &&  dig_sig_id == -1) {
    pdfr_dig_sig_create_dictionaries(enc);
  }

	return 0;
}

void pdfr_encoder_set_physical_page_number(t_pdfrasencoder* enc, int phpageno)
{
	enc->phys_pageno = phpageno;
}

void pdfr_encoder_set_page_front(t_pdfrasencoder* enc, int frontness)
{
	enc->page_front = frontness;
}


typedef struct {
	const pduint8* data;
	size_t count;
} t_stripinfo;

static void onimagedataready(t_datasink *sink, void *eventcookie)
{
	t_stripinfo* pinfo = (t_stripinfo*)eventcookie;
	pd_datasink_put(sink, pinfo->data, 0, pinfo->count);
}

t_pdvalue pdfr_encoder_get_rgb_colorspace(t_pdfrasencoder* enc)
{
    // if there's no current calibrated RGB ColorSpace
	if (IS_NULL(enc->rgbColorspace)) {
        // define the default calibrated RGB colorspace as an ICCBased
        // sRGB colorspace:
        pdfr_encoder_define_rgb_icc_colorspace(enc, NULL, 0);
	}
    // flush the colorspace profile to the output
    t_pdvalue profile = pd_array_get(enc->rgbColorspace.value.arrvalue, 1);
    pd_write_reference_declaration(enc->stm, profile);
    // return the current calibrated RGB colorspace
    return enc->rgbColorspace;
}

t_pdvalue pdfr_encoder_get_calgray_colorspace(t_pdfrasencoder* enc)
{
	double black[3] = { 0.0, 0.0, 0.0 };
	// Should this be D65? [0.9505, 1.0000, 1.0890]?  Does it matter?
	double white[3] = { 1.0, 1.0, 1.0 };
	// "The Gamma  entry shall be present in the CalGray colour space dictionary with a value of 2.2."
	double gamma = 2.2;
	return pd_make_calgray_colorspace(enc->pool, gamma, black, white);
}

t_pdvalue pdfr_encoder_get_colorspace(t_pdfrasencoder* enc)
{
	switch (enc->pixelFormat) {
	case PDFRAS_RGB24:
	case PDFRAS_RGB48:
        // retrieve the current calibrated colorspace, which may be either
        // a CalRGB space or an ICCBased space.
        return pdfr_encoder_get_rgb_colorspace(enc);
	case PDFRAS_BITONAL:
		// "Bitonal images shall be represented by an image XObject dictionary with DeviceGray
		// or CalGray as the value of its ColorSpace entry..."
		if (enc->bitonalUncal) {
			return pdatomvalue(PDA_DeviceGray);
		}
        // else use /CalGray
	case PDFRAS_GRAY8:
	case PDFRAS_GRAY16:
		// "Grayscale images shall be represented by an image XObject dictionary with CalGray
		// as the value of its ColorSpace entry..."
        // Note, DeviceGray and ICCBased are not options.
		return pdfr_encoder_get_calgray_colorspace(enc);
	default:
		break;
	} // switch
	return pderrvalue();
}

static void start_strip_zero(t_pdfrasencoder* enc)
{
    enc->compression = enc->next_page_compression;
    enc->pixelFormat = enc->next_page_pixelFormat;
    enc->colorspace = pdfr_encoder_get_colorspace(enc);
}

int pdfr_encoder_write_strip(t_pdfrasencoder* enc, int rows, const pduint8 *buf, size_t len)
{
    if (enc->strips == 0) {
        // first strip on this page, all strips on page
        // must have same format, compression and colorspace.
        start_strip_zero(enc);
    }
	char stripname[5+12] = "strip";

	e_ImageCompression comp = kCompNone;
	switch (enc->compression) {
	case PDFRAS_CCITTG4:
		comp = kCompCCITT;
		break;
	case PDFRAS_JPEG:
		comp = kCompDCT;
		break;
	default:
		break;
	}
	int bitsPerComponent = 8;
	switch (enc->pixelFormat) {
	case PDFRAS_BITONAL:
		bitsPerComponent = 1;
		break;
	case PDFRAS_GRAY16:
	case PDFRAS_RGB48:
		bitsPerComponent = 16;
		break;
	default:
		break;
	} // switch
	t_stripinfo stripinfo;
	stripinfo.data = buf;
	stripinfo.count = len;
	t_pdvalue image = pd_image_new_simple(enc->pool, enc->xref, onimagedataready, &stripinfo,
		enc->width, rows, bitsPerComponent,
		comp,
		kCCIITTG4, PD_FALSE,			// ignored unless compression is CCITT
		enc->colorspace);
	// get a reference to this (strip) image
	t_pdvalue imageref = pd_xref_makereference(enc->xref, image);
	pditoa(enc->strips, stripname + 5);
	// turn strip name into an atom
	t_pdatom strip = pd_atom_intern(enc->atoms, stripname);
	// add the image to the resources of the current page, with the given name
	pd_page_add_image(enc->currentPage, strip, imageref);
	// flush the image stream
	pd_write_reference_declaration(enc->stm, imageref);
	// adjust total page height:
	enc->height += rows;
	// increment strip count:
	enc->strips++;

	return 0;
}

int pdfr_encoder_get_page_height(t_pdfrasencoder* enc)
{
	return enc->height;
}

// callback to generate the content text for a page.
// it draws the strips of the page in order from top to bottom.
static void content_generator(t_pdcontents_gen *gen, void *cookie)
{
	t_pdfrasencoder* enc = (t_pdfrasencoder*)cookie;
	// compute width & height of page in PDF points
	double W = enc->width / enc->xdpi * 72.0;
	double H = enc->height / enc->ydpi * 72.0;
	// horizontal (x) offset is always 0 - flush to left edge.
	double tx = 0;
	// vertical offset starts at top of page
	double ty = H;
	pdbool succ;
	t_pdvalue res = pd_dict_get(enc->currentPage, PDA_Resources, &succ);
	t_pdvalue xobj = pd_dict_get(res, PDA_XObject, &succ);
	for (int n = 0; n < enc->strips; n++) {
		char stripNname[5+12] = "strip";
		pditoa(n, stripNname + 5);
		// turn strip name into an atom
		t_pdatom stripNatom = pd_atom_intern(enc->atoms, stripNname);
		// find the strip Image resource
		t_pdvalue img = pd_dict_get(xobj, stripNatom, &succ);
		// get its /Height
		t_pdvalue striph = pd_dict_get(img, PDA_Height, &succ);
		// calculate height in Points
		double SH = striph.value.intvalue * 72.0 / enc->ydpi;
		pd_gen_gsave(gen);
		pd_gen_concatmatrix(gen, W, 0, 0, SH, tx, ty-SH);
		pd_gen_xobject(gen, stripNatom);
		pd_gen_grestore(gen);
		ty -= SH;
	}
}

static void update_media_box(t_pdfrasencoder* enc, t_pdvalue page)
{
	pdbool success = PD_FALSE;
	t_pdvalue box = pd_dict_get(page, PDA_MediaBox, &success);
	assert(success);
	assert(IS_ARRAY(box));
	double W = enc->width / enc->xdpi * 72.0;
	double H = enc->height / enc->ydpi * 72.0;
	pd_array_set(box.value.arrvalue, 2, pdfloatvalue(W));
	pd_array_set(box.value.arrvalue, 3, pdfloatvalue(H));
}

static void write_page_metadata(t_pdfrasencoder* enc)
{
	if (enc->page_front >= 0 || enc->phys_pageno >= 0) {
		t_pdvalue modTime = pd_make_now_string(enc->pool);
		t_pdvalue privDict = pd_dict_new(enc->pool, 2);
		if (enc->phys_pageno >= 0) {
			pd_dict_put(privDict, PDA_PhysicalPageNumber, pdintvalue(enc->phys_pageno));
		}
		if (enc->page_front >= 0) {
			pd_dict_put(privDict, PDA_FrontSide, pdboolvalue(enc->page_front == 1));
		}
		t_pdvalue appDataDict = pd_dict_new(enc->pool, 2);
		pd_dict_put(appDataDict, PDA_LastModified, modTime);
		pd_dict_put(appDataDict, PDA_Private, privDict);
		t_pdvalue pieceInfo = pd_dict_new(enc->pool, 2);
		pd_dict_put(pieceInfo, PDA_PDFRaster, appDataDict);
		pd_dict_put(enc->currentPage, PDA_PieceInfo, pieceInfo);
		pd_dict_put(enc->currentPage, PDA_LastModified, modTime);
	}
}

int pdfr_encoder_end_page(t_pdfrasencoder* enc)
{
	if (!IS_NULL(enc->currentPage)) {
		// create a content generator
		t_pdcontents_gen *gen = pd_contents_gen_new(enc->pool, content_generator, enc);
		// create contents object (stream)
		t_pdvalue contents = pd_xref_makereference(enc->xref, pd_contents_new(enc->pool, enc->xref, gen));
		// flush (write) the contents stream
		pd_write_reference_declaration(enc->stm, contents);
		// add the contents to the current page
		pd_dict_put(enc->currentPage, PDA_Contents, contents);
		// update the media box (we didn't really know the height until now)
		update_media_box(enc, enc->currentPage);
		if (enc->rotation != 0) {
			pd_dict_put(enc->currentPage, PDA_Rotate, pdintvalue(enc->rotation));
		}
		// metadata - add to page if any is specified
		write_page_metadata(enc);
		// flush (write) the current page
		pd_write_reference_declaration(enc->stm, enc->currentPage);
		// add the current page to the catalog (page tree)
		pd_catalog_add_page(enc->catalog, enc->currentPage);
		// done with current page:
		enc->currentPage = pdnullvalue();
	}
    // clear one-time page metadata
    enc->phys_pageno = -1;			// unspecified
    enc->page_front = -1;			// unspecified
    return 0;
}

int pdfr_encoder_page_count(t_pdfrasencoder* enc)
{
	int pageCount = -1;
	if (enc) {
		pdbool succ;
		t_pdvalue pagesdict = pd_dict_get(enc->catalog, PDA_Pages, &succ);
		assert(succ);
		if (succ) {
			t_pdvalue count = pd_dict_get(pagesdict, PDA_Count, &succ);
			assert(succ);
			assert(IS_INT(count));
			pageCount = count.value.intvalue;
			if (!IS_NULL(enc->currentPage)) {
				pageCount++;
			}
		}
	}
	return pageCount;
}

void pdfr_encoder_set_AES256_encrypter(t_pdfrasencoder* enc, const char* user_password, const char* owner_password, pdint32 perms)
{
  //todo rt 
  //todo EncryptMetadata

  t_pdencrypter *encrypter = pd_encrypt_new(enc->pool, NULL);
  pd_outstream_set_encrypter(enc->stm, encrypter);

  // Encrypt dictionary goes to trailer
  t_pdvalue stdcfDict = pd_dict_new(enc->pool, 3);
  pd_dict_put(stdcfDict, ((t_pdatom)"Type"), pdatomvalue((t_pdatom)"CryptFilter"));
  pd_dict_put(stdcfDict, ((t_pdatom)"Length"), pdintvalue(32));
  pd_dict_put(stdcfDict, ((t_pdatom)"CFM"), pdatomvalue((t_pdatom)"AESV3"));

  t_pdvalue cfDict = pd_dict_new(enc->pool, 1);
  pd_dict_put(cfDict, ((t_pdatom)"StdCF"), stdcfDict);

  t_pdvalue encrypt = pd_dict_new(enc->pool, 13);
  t_pdvalue encryptref = pd_xref_makereference(enc->xref, encrypt);
  encrypter->id_encrypt = pd_reference_object_number(encryptref);
  
  pd_dict_put(enc->trailer, ((t_pdatom)"Encrypt"), encryptref);

  pd_dict_put(encrypt, ((t_pdatom)"Length"), pdintvalue(256));
  pd_dict_put(encrypt, ((t_pdatom)"Filter"), pdatomvalue((t_pdatom)"Standard"));
  pd_dict_put(encrypt, ((t_pdatom)"EncryptMetadata"), pdboolvalue(PD_FALSE));
  pd_dict_put(encrypt, ((t_pdatom)"V"), pdintvalue(5));
  pd_dict_put(encrypt, ((t_pdatom)"R"), pdintvalue(6));
  pd_dict_put(encrypt, ((t_pdatom)"P"), pdintvalue(perms));
  pd_dict_put(encrypt, ((t_pdatom)"StrF"), pdatomvalue((t_pdatom)"StdCF"));
  pd_dict_put(encrypt, ((t_pdatom)"StmF"), pdatomvalue((t_pdatom)"StdCF"));
  pd_dict_put(encrypt, ((t_pdatom)"CF"), cfDict);

  //todo - calculate AES256 specific values
  pd_encrypt_compute_file_encryption_key(encrypter);
  pd_encrypt_compute_Alg8(encrypter, user_password);
  if (owner_password == NULL || strlen(owner_password) == 0)
    pd_encrypt_compute_Alg9(encrypter, user_password);
  else 
    pd_encrypt_compute_Alg9(encrypter, owner_password);

  pd_encrypt_compute_Alg10(encrypter, perms);

  pd_dict_put(encrypt, ((t_pdatom)"O"), pdstringvalue(pd_string_new_binary(enc->pool, encrypter->o_length, encrypter->o)));
  pd_dict_put(encrypt, ((t_pdatom)"OE"), pdstringvalue(pd_string_new_binary(enc->pool, encrypter->oe_length, encrypter->oe)));
  pd_dict_put(encrypt, ((t_pdatom)"U"), pdstringvalue(pd_string_new_binary(enc->pool, encrypter->u_length, encrypter->u)));
  pd_dict_put(encrypt, ((t_pdatom)"UE"), pdstringvalue(pd_string_new_binary(enc->pool, encrypter->ue_length, encrypter->ue)));
  pd_dict_put(encrypt, ((t_pdatom)"Perms"), pdstringvalue(pd_string_new_binary(enc->pool, 16, encrypter->perms)));
}


EVP_PKEY* digsig_pkey = NULL;
X509* digsig_cert = NULL;
pdbool is_digsig = PD_FALSE;
pduint32 dig_sig_V_offset;
pduint32 dig_sig_id=-1;

// if out_buffer==NULL then only size is computed
int DigitaSignature_SigData(unsigned char *in_buffer, int in_buffer_length, unsigned char *out_buffer)
{
  // signing buffer with certificate
  int out_buffer_length = 0;
  BIO* inputbio = BIO_new(BIO_s_mem());
  BIO_write(inputbio, in_buffer, in_buffer_length );
  PKCS7 *pkcs7;
  int flags = PKCS7_DETACHED | PKCS7_BINARY;
  pkcs7 = PKCS7_sign(digsig_cert, digsig_pkey, NULL, inputbio, flags);
  BIO_free(inputbio);

  // going to acquire encrypted data
  if (pkcs7) {
    BIO* outputbio = BIO_new(BIO_s_mem());
    i2d_PKCS7_bio(outputbio, pkcs7);
    BUF_MEM* mem = NULL;
    BIO_get_mem_ptr(outputbio, &mem);
    if (mem && mem->data && mem->length) {
      // mem->length is supposed to be half of signed_len_in_hex
      // because /Contents is written in hex (so 2 characters for each byte)
      out_buffer_length = mem->length;
      if (out_buffer) memcpy(out_buffer, mem->data, out_buffer_length);
    }
    BIO_free(outputbio);
    PKCS7_free(pkcs7);
  }
  return out_buffer_length;
}

void pdfr_encoder_set_digital_signature(t_pdfrasencoder* enc, const char *certificate_file, const char* password)
{
    /*
    << /ByteRange[0 27783 30321 527] 
    /Contents<0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000>
    /Type /Sig 
    /Filter /Adobe.PPKLite 
    /SubFilter /adbe.pkcs7.detached 
    /Reason(???) 
    /Location(??) 
    /Name(??) 
    /ContactInfo(roman.toda@gmail.com) 
    /M(D : 20160428133243 + 02'00') >>

    <</Type/Annot
      /Subtype/Widget
      /Rect[ 0 0 0 0]
      /P 12 0 R 
      /FT/Sig
      /F 132
      /T(Sig1)
      /AP<</N 32 0 R >>
      /V 33 0 R  >>
    */
  //t_pdencrypter *encrypter = pd_encrypt_new(enc->pool, NULL);
  //pd_outstream_set_encrypter(enc->stm, encrypter);

  PKCS12 *pkcs12;
  FILE *pfx_file;
  STACK_OF(X509)* ca = NULL;

  // acquiring data from PFX certificate file
  pfx_file = fopen(certificate_file, "rb");
  if (!pfx_file)
    return;
  pkcs12 = d2i_PKCS12_fp(pfx_file, NULL);
  fclose(pfx_file);
  if (!pkcs12)
    return;

  if (!PKCS12_parse(pkcs12, password, &digsig_pkey, &digsig_cert, &ca)) {
    PKCS12_free(pkcs12);
    return;
  }
  PKCS12_free(pkcs12);

  is_digsig = PD_TRUE;
  dig_sig_id = -1;
}

// we need to create dictionaries only when we have first page
void pdfr_dig_sig_create_dictionaries(t_pdfrasencoder* enc)
{
  pdbool succ;
  // Create AcroForm entry in the Catalog
  t_pdvalue acro_form = pd_dict_get(enc->catalog, (t_pdatom)"AcroForm", &succ);
  if (!succ) {
    acro_form = pd_dict_new(enc->pool, 2);
    t_pdvalue acro_form_ref = pd_xref_makereference(enc->xref, acro_form);
    pd_dict_put(enc->catalog, ((t_pdatom)"AcroForm"), acro_form_ref);
  }

  // Filling AcroForm
  //rt check if SigFlags already exists (multiple signing?)
  pd_dict_put(acro_form, ((t_pdatom)"SigFlags"), pdintvalue(3));

  //Creating /Fields array
  t_pdvalue fields = pd_dict_get(enc->catalog, (t_pdatom)"Fields", &succ);
  if (!succ) {
    fields = pdarrayvalue(pd_array_new(enc->pool, 2));
    t_pdvalue fields_ref = pd_xref_makereference(enc->xref, fields);
    pd_dict_put(acro_form, ((t_pdatom)"Fields"), fields_ref);
  }

  // Preparing Field and appending to the Fields array
  t_pdvalue signature_field = pd_dict_new(enc->pool, 5);
  t_pdvalue signature_field_ref = pd_xref_makereference(enc->xref, signature_field);
  pd_array_add(fields.value.arrvalue, signature_field_ref);

  //Enter paramaters to the /Field
  //rt generate name
  char t[] = "Sig_1";
  pd_dict_put(signature_field, ((t_pdatom)"T"), pdstringvalue(pd_string_new(enc->pool, strlen(t), t)));
  pd_dict_put(signature_field, ((t_pdatom)"FT"), pdatomvalue((t_pdatom)"Sig"));
  pd_dict_put(signature_field, ((t_pdatom)"Type"), pdatomvalue((t_pdatom)"Annot"));
  pd_dict_put(signature_field, ((t_pdatom)"SubType"), pdatomvalue((t_pdatom)"Widget"));
  pd_dict_put(signature_field, ((t_pdatom)"F"), pdintvalue(132));

  t_pdarray *field_rect_arr = pd_array_new(enc->pool, 4);
  pd_array_add(field_rect_arr, pdintvalue(0));
  pd_array_add(field_rect_arr, pdintvalue(0));
  pd_array_add(field_rect_arr, pdintvalue(0));
  pd_array_add(field_rect_arr, pdintvalue(0));
  pd_dict_put(signature_field, ((t_pdatom)"Rect"), pdarrayvalue(field_rect_arr));

  pd_dict_put(signature_field, ((t_pdatom)"P"), enc->currentPage);

  //rt add to Annots array
  //rt Add AP

  // Preparing /V dictionary 
  //rt - these are hardcoded for now
  char reason[] = "Reason to sign document";
  char location[] = "Somewhere over the rainbow";
  char name[] = "Roman Toda";
  char contact_info[] = "roman.toda@gmail.com";
  char m[] = "D:20160428133243+02'00'";
  char content[1024];

  // calculating lenght of the Content just to have accurate size 
  unsigned char random_buff[10];
  int random_buff_size = 1;
  int signature_length = 0;
  signature_length = DigitaSignature_SigData(random_buff, random_buff_size, NULL);
  signature_length = signature_length + 20;

  t_pdvalue v_dict = pd_dict_new(enc->pool, 3);
  pd_dict_put(v_dict, ((t_pdatom)"Contents"), pdstringvalue(pd_string_new_binary(enc->pool, signature_length, content)));
  pd_dict_put(v_dict, ((t_pdatom)"Type"), pdatomvalue((t_pdatom)"Sig"));
  pd_dict_put(v_dict, ((t_pdatom)"Filter"), pdatomvalue((t_pdatom)"Adobe.PPKLite"));
  pd_dict_put(v_dict, ((t_pdatom)"SubFilter"), pdatomvalue((t_pdatom)"adbe.pkcs7.detached"));

  t_pdarray *byterange_arr = pd_array_new(enc->pool, 4);
  pd_array_add(byterange_arr, pdintvalue(2147483647));
  pd_array_add(byterange_arr, pdintvalue(2147483647));
  pd_array_add(byterange_arr, pdintvalue(2147483647));
  pd_array_add(byterange_arr, pdintvalue(2147483647));
  pd_dict_put(v_dict, ((t_pdatom)"ByteRange"), pdarrayvalue(byterange_arr));

  pd_dict_put(v_dict, ((t_pdatom)"Reason"), pdstringvalue(pd_string_new(enc->pool, strlen(reason), reason)));
  pd_dict_put(v_dict, ((t_pdatom)"Location"), pdstringvalue(pd_string_new(enc->pool, strlen(location), location)));
  pd_dict_put(v_dict, ((t_pdatom)"Name"), pdstringvalue(pd_string_new(enc->pool, strlen(name), name)));
  pd_dict_put(v_dict, ((t_pdatom)"ContactInfo"), pdstringvalue(pd_string_new(enc->pool, strlen(contact_info), contact_info)));
  pd_dict_put(v_dict, ((t_pdatom)"M"), pdstringvalue(pd_string_new(enc->pool, strlen(m), m)));

  // Insert V into the Filed dictionary
  t_pdvalue v_dict_ref = pd_xref_makereference(enc->xref, v_dict);
  pd_dict_put(signature_field, ((t_pdatom)"V"), v_dict_ref);
  dig_sig_id = pd_reference_object_number(v_dict_ref);
}

void pdfr_encoder_end_digital_signature(FILE* pdf_file)
{
  // Reading V dictionary 
  // going to calculate Byteranges and update ByteRange entry
  // then sign the file and then update Contents

  pduint32 offset1 = 0;
  pduint32 length1 = 0;
  pduint32 offset2 = 0;
  pduint32 length2 = 0;

  unsigned char buffer[5000];
  fseek(pdf_file, 0L, SEEK_END);
  length2 = ftell(pdf_file);
  fseek(pdf_file, dig_sig_V_offset, SEEK_SET);
  fread((unsigned char *)buffer, 1, sizeof(buffer), pdf_file);

  char *p = strstr(buffer, "/Contents <");
  length1 = dig_sig_V_offset + p - buffer + 10;
  while (*p != '>') p++;
  offset2 = dig_sig_V_offset + p - buffer+1;
  length2 -= offset2;
  p = strstr(buffer, "/ByteRange [");
  fseek(pdf_file, dig_sig_V_offset+(p-buffer+12), SEEK_SET);

  sprintf(buffer, "%d %d %d %d", offset1, length1, offset2, length2);
  while (strlen(buffer) < 45) strcat(buffer, " ");
  fwrite((unsigned char *)buffer, 1, strlen(buffer), pdf_file);

  // buffer for data that we need to sign
  unsigned char *buffer_to_sign = (unsigned char*)malloc(length1 + length2);

  // preparing buffer for signature 
  int signed_len_in_hex = offset2 - length1 - 2;
  int signed_len_in_bytes = 0;

  //// we will store signature here
  unsigned char *signed_data = (unsigned char*)malloc(signed_len_in_hex);

  //hex interpretation of signature. We must allocate space of ending \0
  unsigned char *signed_data_hex = (unsigned char*)malloc(signed_len_in_hex + 1);
  memset(signed_data_hex, 0, signed_len_in_hex + 1);
  memset(signed_data, 0, signed_len_in_hex);

  // reading file (except /Contents) to single buffer
  // pdf defines 2 buffers from beginning of the file to the start 
  // of empty space and then the rest 
  fseek(pdf_file, offset1, SEEK_SET);
  fread((unsigned char *)buffer_to_sign, 1, length1, pdf_file);
  fseek(pdf_file, offset2, SEEK_SET);
  fread((unsigned char *)(buffer_to_sign + length1), 1, length2, pdf_file);

  // signing buffer with certificate
  BIO* inputbio = BIO_new(BIO_s_mem());
  BIO_write(inputbio, buffer_to_sign, (int)(length1 + length2));
  PKCS7 *pkcs7;
  int flags = PKCS7_DETACHED | PKCS7_BINARY;
  pkcs7 = PKCS7_sign(digsig_cert, digsig_pkey, NULL, inputbio, flags);
  BIO_free(inputbio);

  // going to acquire encrypted data
  if (pkcs7) {
    BIO* outputbio = BIO_new(BIO_s_mem());
    i2d_PKCS7_bio(outputbio, pkcs7);
    BUF_MEM* mem = NULL;
    BIO_get_mem_ptr(outputbio, &mem);
    if (mem && mem->data && mem->length) {
      // mem->length is supposed to be half of signed_len_in_hex
      // because /Contents is written in hex (so 2 characters for each byte)
      signed_len_in_bytes = mem->length;
      memcpy(signed_data, mem->data, signed_len_in_bytes);
    }
    BIO_free(outputbio);
    PKCS7_free(pkcs7);

    // converting to hex
    for (int i = 0; i < signed_len_in_bytes; i++)
      sprintf((char*)&signed_data_hex[i * 2], "%02X", signed_data[i]);

    // writing directly to /Content entry
    fseek(pdf_file, offset1 + length1 + 1, SEEK_SET);
    fwrite(signed_data_hex, 1, signed_len_in_bytes * 2, pdf_file);
  }
  free(buffer_to_sign);
  free(signed_data);
  free(signed_data_hex);
}


long pdfr_encoder_bytes_written(t_pdfrasencoder* enc)
{
	return pd_outstream_pos(enc->stm);
}

static int pdfr_sig_handler(t_pdoutstream *stm, void* cookie, PdfOutputEventCode eventid)
{
    pd_puts(stm, "%PDF-raster-" PDFRASTER_SPEC_VERSION "\n");
    return 0;
}

void pdfr_encoder_end_document(t_pdfrasencoder* enc)
{
    t_pdoutstream* stm = enc->stm;
	pdfr_encoder_end_page(enc);
	// remember to write our PDF/raster signature marker
    pd_outstream_set_event_handler(stm, PDF_EVENT_BEFORE_STARTXREF, pdfr_sig_handler, NULL);
	pd_write_endofdocument(stm, enc->xref, enc->catalog, enc->info, enc->trailer);

  // Note: we leave all the final data structures intact in case the client
	// has questions, like 'how many pages did we write?' or 'how big was the output file?'.
}

void pdfr_encoder_destroy(t_pdfrasencoder* enc)
{
	if (enc) {
		// free everything in the pool associated
		// with this encoder. Including the pool
		// and the encoder struct.
		struct t_pdmempool *pool = enc->pool;
		pd_alloc_free_pool(pool);
	}
}

