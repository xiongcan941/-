#ifndef UTILS_BITMAP_H
#define UTILS_BITMAP_H

#define INDEX_FROM_BIT(a) (a/32)
#define OFFSET_FROM_BIT(a) (a%32)
// argument struct for common isr_handler
typedef struct bit_map {
  unsigned int* array;
  unsigned char alloc_array;
  int array_size;  // size of the array
  int total_bits;
} bitmap_t;

void bitmap_init(bitmap_t* this, unsigned int* array, int total_bits) 
{
  int i = 0;
  this->total_bits = total_bits;
  this->array_size = total_bits / 32;
  if (array == NULL) {
    array = (unsigned int*)vzalloc(this->array_size * 4);
    this->alloc_array = true;
  } else {
    this->alloc_array = false;
  }
  for (i = 0; i < this->array_size; i++) {
    array[i] = 0;
  }
  this->array = array;
}

bitmap_t bitmap_create(unsigned int* array, int total_bits) {
  bitmap_t ret;
  bitmap_init(&ret, array, total_bits);
  return ret;
}

void bitmap_set_bit(bitmap_t* this, unsigned int bit) {
  unsigned int idx = INDEX_FROM_BIT(bit);
  unsigned off = OFFSET_FROM_BIT(bit);
  this->array[idx] |= (0x1 << off);
}

void bitmap_clear_bit(bitmap_t* this, unsigned int bit) {
  unsigned int idx = INDEX_FROM_BIT(bit);
  unsigned int off = OFFSET_FROM_BIT(bit);
  this->array[idx] &= ~(0x1 << off);
}

bool bitmap_test_bit(bitmap_t* this, unsigned int bit) {
  unsigned int idx = INDEX_FROM_BIT(bit);
  unsigned int off = OFFSET_FROM_BIT(bit);
  return (this->array[idx] & (0x1 << off)) != 0;
}

bool bitmap_find_first_free(bitmap_t* this, unsigned int* bit) {
  unsigned int i, j;
  for (i = 0; i < this->array_size; i++) {
    unsigned int ele = this->array[i];
    if (ele != 0xFFFFFFFF) {
      for (j = 0; j < 32; j++) {
        if (!(ele & (0x1 << j))) {
          *bit = i * 32 + j;
          return true;
        }
      }
    }
  }

  return false;
}

bool bitmap_allocate_first_free(bitmap_t* this, unsigned int* bit) {
  bool success = bitmap_find_first_free(this, bit);
  if (!success) {
    return false;
  }

  bitmap_set_bit(this, *bit);
  return true;
}

void bitmap_clear1(bitmap_t* this) {
  unsigned int i = 0;
  for (i = 0; i < this->array_size; i++) {
    this->array[i] = 0;
  }
}

bool bitmap_expand(bitmap_t* this, unsigned int expand_size) {
  int i = 0;
  unsigned int new_size = expand_size;
  unsigned int new_array_size = new_size / 32;
  unsigned int* array = (unsigned int*)vzalloc(new_array_size * 4);
  for (i = 0; i < new_array_size; i++) {
    array[i] = 0;
  }
  for (i = 0; i < this->array_size; i++) {
    array[i] = this->array[i];
  }

  if (this->alloc_array) {
    vfree(this->array);
  }
  this->total_bits = new_size;
  this->array_size = new_array_size;
  this->alloc_array = true;
  this->array = array;
  return true;
}

void bitmap_destroy(bitmap_t* this) {
  if (this->alloc_array) {
    //monitor_printf("destroyed user_thread_stack_indexes %x\n", this->array);
    vfree(this->array);
  }
}
#endif
