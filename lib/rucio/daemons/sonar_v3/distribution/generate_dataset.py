# Generates files filled with random data.
import os
import sys

if __name__ == '__main__':
    if len(sys.argv) < 3:
        msg = """
    Usage: python generate_dataset.py <dataset_name> <number of files> <size of each file in bytes>
        """
        print(msg)
        sys.exit(0)
    dataset_name = sys.argv[1]
    file_number = int(sys.argv[2])
    file_size = int(sys.argv[3])

    if not os.path.exists(dataset_name):
        os.makedirs(dataset_name)

    for i in range(file_number):
        tmp_file = open('./'+dataset_name+'/'+dataset_name+'.file'+str(i),'w+')
        tmp_file.write(os.urandom(file_size))
        tmp_file.close()



