import os, fnmatch

def renameFiles(directory, prefix, filePattern):
    for path, dirs, files in os.walk(os.path.abspath(directory)):
        for filename in fnmatch.filter(files, filePattern):
            if prefix == filename[0:len(prefix)]:
                os.rename(os.path.join(path, filename),
                          os.path.join(path, filename[len(prefix):]))
            else:
                os.rename(os.path.join(path, filename),
                          os.path.join(path, prefix + filename))

def renameFile(directory, oldfile, newfile):
    os.rename(os.path.join(directory, oldfile), os.path.join(directory, newfile))
            
                
renameFiles("./", "1905072_", "*.py")
