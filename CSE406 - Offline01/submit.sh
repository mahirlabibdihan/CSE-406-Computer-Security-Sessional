rm upload -r >/dev/null 2>&1
mkdir upload/1905072 -p
cp workspace/*.py upload/1905072
cp rename.py upload/1905072
cd upload/1905072/
python rename.py
cd ..
zip 1905072.zip 1905072/*
echo "Files uploaded at upload/1905072.zip"
